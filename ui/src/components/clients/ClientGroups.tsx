/**
 * Client groups (GET/POST /api/client-groups, PUT/DELETE .../{id}): sets of
 * devices, by address or network, with restrictions on top of the policy
 * every client gets: lists that apply to the group only, a time window, and
 * allowlist-only egress. A group only tightens. A list is offered here once
 * its scope is "Groups only" on the Blacklists page.
 */
import { useId, useState, type FormEvent } from 'react';
import { Link } from 'react-router';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { api, getData, getErrorMessage } from '../../lib/api';
import { cn } from '../../lib/utils';
import { useConfirm } from '../../hooks/useConfirm';
import type { ClientGroup, ListSource } from '../../types';
import { sourceTitle } from '../blacklists/lists';
import { Section } from '../ui/Section';
import { Button } from '../ui/Button';
import { Badge } from '../ui/Badge';
import { Notice } from '../ui/Notice';
import { Switch } from '../ui/Switch';
import { DataTable, type Column } from '../ui/DataTable';

const groupsKey = ['client-groups'] as const;

const INPUT = 'h-9 w-full min-w-0 rounded-control border border-line-strong bg-surface px-3 text-sm text-ink focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent';
// The same rule as the backend (database.NormalizeClientGroup).
const NAME_RULE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$/;

/** Squid's day letters, in the order a week reads here. */
const DAYS: { letter: string; label: string; name: string }[] = [
  { letter: 'M', label: 'Mon', name: 'Monday' },
  { letter: 'T', label: 'Tue', name: 'Tuesday' },
  { letter: 'W', label: 'Wed', name: 'Wednesday' },
  { letter: 'H', label: 'Thu', name: 'Thursday' },
  { letter: 'F', label: 'Fri', name: 'Friday' },
  { letter: 'A', label: 'Sat', name: 'Saturday' },
  { letter: 'S', label: 'Sun', name: 'Sunday' },
];

/** The blacklists whose sources can apply to groups only. */
const SCOPED_LISTS = [
  { path: 'ip-blacklist', label: 'Blocked IPs' },
  { path: 'domain-blacklist', label: 'Blocked domains' },
] as const;

/** "Mon to Fri, 07:00 to 21:00": three or more days in a row read as a range. */
function scheduleText(s: ClientGroup['schedule']): string {
  if (!s) return '';
  const on = DAYS.map((d) => s.days.includes(d.letter));
  const parts: string[] = [];
  for (let i = 0; i < DAYS.length; i++) {
    if (!on[i]) continue;
    let j = i;
    while (j + 1 < DAYS.length && on[j + 1]) j++;
    parts.push(j - i >= 2 ? `${DAYS[i].label} to ${DAYS[j].label}` : DAYS.slice(i, j + 1).map((d) => d.label).join(', '));
    i = j;
  }
  return `${on.every(Boolean) ? 'Every day' : parts.join(', ')}, ${s.start} to ${s.end}`;
}

interface Draft {
  id: number | null;
  name: string;
  description: string;
  members: string;
  lists: number[];
  limitHours: boolean;
  days: string;
  start: string;
  end: string;
  allowlistOnly: boolean;
}

const EMPTY: Draft = {
  id: null, name: '', description: '', members: '', lists: [],
  limitHours: false, days: 'MTWHF', start: '07:00', end: '21:00', allowlistOnly: false,
};

function draftOf(g: ClientGroup): Draft {
  return {
    id: g.id,
    name: g.name,
    description: g.description,
    members: g.members.join('\n'),
    lists: g.lists,
    limitHours: g.schedule !== null,
    days: g.schedule?.days ?? EMPTY.days,
    start: g.schedule?.start ?? EMPTY.start,
    end: g.schedule?.end ?? EMPTY.end,
    allowlistOnly: g.allowlist_only,
  };
}

function GroupEditor({ initial, sources, onDone }: {
  initial: Draft;
  sources: { id: number; title: string; list: string }[];
  onDone: (saved: boolean) => void;
}) {
  const id = useId();
  const [d, setD] = useState<Draft>(initial);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setD((prev) => ({ ...prev, [k]: v }));
  const name = d.name.trim();
  const nameInvalid = name !== '' && !NAME_RULE.test(name);
  const windowInvalid = d.limitHours && (d.days === '' || d.end <= d.start);

  const save = async (e: FormEvent) => {
    e.preventDefault();
    if (name === '' || nameInvalid || windowInvalid || saving) return;
    setSaving(true);
    setError('');
    const body = {
      name,
      description: d.description.trim(),
      members: d.members.split(/[\s,]+/).map((m) => m.trim()).filter(Boolean),
      lists: d.lists,
      schedule: d.limitHours ? { days: d.days, start: d.start, end: d.end } : null,
      allowlist_only: d.allowlistOnly,
    };
    try {
      if (d.id === null) await api.post('client-groups', body);
      else await api.put(`client-groups/${d.id}`, body);
      toast.success(d.id === null ? `Group "${name}" created` : `Group "${name}" saved`);
      onDone(true);
    } catch (err) {
      setError(`Not saved: ${getErrorMessage(err, 'the backend did not answer')}.`);
    } finally {
      setSaving(false);
    }
  };

  const toggleDay = (letter: string) =>
    set('days', d.days.includes(letter) ? d.days.replace(letter, '') : d.days + letter);
  const toggleList = (sid: number) =>
    set('lists', d.lists.includes(sid) ? d.lists.filter((x) => x !== sid) : [...d.lists, sid]);

  return (
    <form onSubmit={(e) => void save(e)} aria-label={d.id === null ? 'New client group' : `Edit ${initial.name}`}
      className="flex flex-col gap-4 rounded-panel border border-line bg-surface-muted p-4">
      <div className="flex flex-wrap gap-3">
        <div className="flex min-w-48 flex-1 flex-col gap-1.5">
          <label htmlFor={`${id}-name`} className="text-sm font-medium text-ink">Name</label>
          <input id={`${id}-name`} value={d.name} onChange={(e) => set('name', e.target.value)} placeholder="e.g. kids"
            autoComplete="off" aria-invalid={nameInvalid || undefined}
            aria-describedby={nameInvalid ? `${id}-name-error` : undefined}
            className={cn(INPUT, nameInvalid && 'border-danger-line')} />
        </div>
        <div className="flex min-w-48 flex-[2_1_16rem] flex-col gap-1.5">
          <label htmlFor={`${id}-desc`} className="text-sm font-medium text-ink">Description (optional)</label>
          <input id={`${id}-desc`} value={d.description} onChange={(e) => set('description', e.target.value)} maxLength={200} className={INPUT} />
        </div>
      </div>
      {nameInvalid && <p id={`${id}-name-error`} className="text-sm text-danger">Letters, digits, spaces, dots, underscores and hyphens, up to 40, starting with a letter or digit.</p>}

      <div className="flex flex-col gap-1.5">
        <label htmlFor={`${id}-members`} className="text-sm font-medium text-ink">Members</label>
        <textarea id={`${id}-members`} value={d.members} onChange={(e) => set('members', e.target.value)} rows={3}
          aria-describedby={`${id}-members-help`} placeholder="e.g. 192.168.1.20"
          className="min-h-20 w-full rounded-control border border-line-strong bg-surface px-3 py-2 font-mono text-sm text-ink focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent" />
        <p id={`${id}-members-help`} className="text-xs text-ink-muted">
          Addresses or networks, one per line, as the proxy sees them (the list of clients above shows them).
        </p>
      </div>

      <fieldset className="flex flex-col gap-2">
        <legend className="mb-1 text-sm font-medium text-ink">Lists for this group only</legend>
        {sources.length === 0 ? (
          <p className="text-sm text-ink-muted">
            No list applies to groups only yet. On <Link to="/blacklists" className="text-accent underline underline-offset-2">Blacklists</Link>,
            set a list&apos;s <span className="font-medium">Applies to</span> to groups only, and it appears here.
          </p>
        ) : sources.map((s) => (
          <label key={s.id} className="flex items-center gap-2 text-sm text-ink">
            <input type="checkbox" checked={d.lists.includes(s.id)} onChange={() => toggleList(s.id)} className="h-4 w-4 accent-[var(--ds-accent)]" />
            <span>{s.title}</span>
            <span className="text-xs text-ink-muted">{s.list}</span>
          </label>
        ))}
      </fieldset>

      <div className="flex flex-col gap-2">
        <div className="flex items-center gap-2.5">
          <Switch labelledBy={`${id}-hours`} checked={d.limitHours} onChange={(v) => set('limitHours', v)} />
          <span id={`${id}-hours`} className="text-sm font-medium text-ink">Only during set hours</span>
        </div>
        {d.limitHours && (
          <div className="flex flex-col gap-2 pl-1">
            <fieldset className="flex flex-wrap gap-x-3 gap-y-1">
              <legend className="sr-only">Days</legend>
              {DAYS.map((day) => (
                <label key={day.letter} className="flex items-center gap-1.5 text-sm text-ink">
                  <input type="checkbox" checked={d.days.includes(day.letter)} onChange={() => toggleDay(day.letter)}
                    aria-label={day.name} className="h-4 w-4 accent-[var(--ds-accent)]" />
                  <span aria-hidden="true">{day.label}</span>
                </label>
              ))}
            </fieldset>
            <div className="flex flex-wrap items-center gap-2 text-sm text-ink">
              <label htmlFor={`${id}-start`}>From</label>
              <input id={`${id}-start`} type="time" value={d.start} onChange={(e) => set('start', e.target.value)} className={cn(INPUT, 'w-32')} />
              <label htmlFor={`${id}-end`}>to</label>
              <input id={`${id}-end`} type="time" value={d.end} onChange={(e) => set('end', e.target.value)} className={cn(INPUT, 'w-32')} />
            </div>
            {windowInvalid && (
              <p className="text-sm text-danger">
                {d.days === '' ? 'Choose at least one day.' : 'The window ends after it starts, on the same day: 21:00 to 07:00 is not one window.'}
              </p>
            )}
          </div>
        )}
      </div>

      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-2.5">
          <Switch labelledBy={`${id}-allow`} describedBy={`${id}-allow-help`} checked={d.allowlistOnly} onChange={(v) => set('allowlistOnly', v)} />
          <span id={`${id}-allow`} className="text-sm font-medium text-ink">Only the destinations on the allowlist</span>
        </div>
        <p id={`${id}-allow-help`} className="text-xs text-ink-muted">
          The group reaches only the destinations on <Link to="/egress" className="text-accent underline underline-offset-2">Egress</Link>, LAN
          destinations and IP exceptions, whether or not default-deny is on for everyone.
        </p>
      </div>

      {error && <p role="alert" className="text-sm text-danger">{error}</p>}
      <div className="flex gap-2">
        <Button type="submit" variant="primary" disabled={name === '' || nameInvalid || windowInvalid || saving}>
          {saving ? 'Saving...' : d.id === null ? 'Create group' : 'Save group'}
        </Button>
        <Button type="button" variant="ghost" onClick={() => onDone(false)}>Cancel</Button>
      </div>
    </form>
  );
}

export function ClientGroups() {
  const queryClient = useQueryClient();
  const { confirm, dialog } = useConfirm();
  const groups = useQuery({ queryKey: groupsKey, queryFn: () => getData<ClientGroup[]>('client-groups'), retry: false });
  const ipSources = useQuery({ queryKey: ['lists', 'ip-blacklist', 'sources'], queryFn: () => getData<ListSource[]>('ip-blacklist/sources') });
  const domainSources = useQuery({ queryKey: ['lists', 'domain-blacklist', 'sources'], queryFn: () => getData<ListSource[]>('domain-blacklist/sources') });
  const [editing, setEditing] = useState<Draft | null>(null);

  const groupSources = [
    ...(ipSources.data ?? []).map((s) => ({ s, list: SCOPED_LISTS[0].label })),
    ...(domainSources.data ?? []).map((s) => ({ s, list: SCOPED_LISTS[1].label })),
  ].filter(({ s }) => s.id !== null && s.scope === 'groups').map(({ s, list }) => ({ id: s.id as number, title: sourceTitle(s), list }));
  const titleOf = (sid: number) => groupSources.find((s) => s.id === sid)?.title ?? `List ${sid}`;

  const remove = async (g: ClientGroup) => {
    const ok = await confirm({
      title: `Delete the group "${g.name}"?`,
      body: 'Its members get the policy every client gets. The lists it used stay, for groups only.',
      confirmLabel: 'Delete group',
      destructive: true,
    });
    if (!ok) return;
    try {
      await api.delete(`client-groups/${g.id}`);
      toast.success(`Deleted "${g.name}"`);
    } catch (err) {
      toast.error(getErrorMessage(err, 'The group was not deleted'));
    } finally {
      void queryClient.invalidateQueries({ queryKey: groupsKey });
    }
  };

  const columns: Column<ClientGroup>[] = [
    {
      id: 'name', header: 'Group',
      cell: (g) => (
        <div className="flex flex-col gap-0.5">
          <span className="font-medium text-ink">{g.name}</span>
          {g.description && <span className="text-xs text-ink-muted">{g.description}</span>}
          {/* On a phone the Members column is hidden: its count is here. */}
          <span className="text-xs text-ink-muted sm:hidden">
            {g.members.length === 0 ? 'No members' : g.members.length === 1 ? '1 member' : `${g.members.length} members`}
          </span>
        </div>
      ),
    },
    {
      id: 'members', header: 'Members', hideOnPhone: true,
      cell: (g) => (g.members.length === 0
        ? <span className="text-ink-muted">None: no rules apply</span>
        : <span className="font-mono text-xs">{g.members.slice(0, 2).join(', ')}{g.members.length > 2 ? ` and ${g.members.length - 2} more` : ''}</span>),
    },
    {
      id: 'restrictions', header: 'Restrictions',
      cell: (g) => {
        const tags = [
          ...g.lists.map((sid) => <Badge key={`l${sid}`} tone="accent" className="whitespace-normal">{titleOf(sid)}</Badge>),
          ...(g.schedule ? [<Badge key="h" tone="neutral" className="whitespace-normal">{scheduleText(g.schedule)}</Badge>] : []),
          ...(g.allowlist_only ? [<Badge key="a" tone="warning" className="whitespace-normal">Allowlist only</Badge>] : []),
        ];
        return tags.length ? <div className="flex flex-wrap gap-1">{tags}</div> : <span className="text-ink-muted">None</span>;
      },
    },
    {
      id: 'actions', header: 'Actions', headerHidden: true, align: 'right',
      cell: (g) => (
        <div className="flex flex-col items-end gap-2 sm:flex-row sm:justify-end">
          <Button size="sm" onClick={() => setEditing(draftOf(g))} aria-label={`Edit ${g.name}`}>Edit</Button>
          <Button size="sm" variant="danger-outline" onClick={() => void remove(g)} aria-label={`Delete ${g.name}`}>Delete</Button>
        </div>
      ),
    },
  ];

  return (
    <Section
      title="Client groups"
      description="Devices, by address or network, with restrictions on top of the policy every client gets: lists for the group only, set hours, or only the allowlist. A group only tightens; a device in two groups gets both."
    >
      <div className="flex flex-col gap-4">
        {editing === null && (
          <div><Button size="sm" variant="primary" onClick={() => setEditing(EMPTY)}>New group</Button></div>
        )}
        {editing && (
          <GroupEditor
            key={editing.id ?? 'new'}
            initial={editing}
            sources={groupSources}
            onDone={(saved) => {
              setEditing(null);
              if (saved) void queryClient.invalidateQueries({ queryKey: groupsKey });
            }}
          />
        )}
        {groups.isError && !groups.isPending ? (
          <Notice tone="danger" title="client-groups did not answer">{getErrorMessage(groups.error, 'The groups could not be read')}</Notice>
        ) : (
          <DataTable
            caption="Client groups"
            columns={columns}
            rows={groups.data ?? []}
            rowKey={(g) => String(g.id)}
            loading={groups.isPending}
            onRetry={() => void groups.refetch()}
            empty={{ title: 'No client groups', description: 'Create one to give some devices their own lists, hours or allowlist.' }}
          />
        )}
      </div>
      {dialog}
    </Section>
  );
}
