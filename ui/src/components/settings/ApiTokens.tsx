/**
 * API tokens (GET/POST /api/tokens, DELETE /api/tokens/{id}): what scripts
 * and tools sign in with instead of the admin password. A token's value is
 * shown once, when it is created; the backend keeps only its hash. Revoking
 * a token stops it at once.
 */
import { useEffect, useId, useRef, useState, type FormEvent } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { api, getData, getErrorMessage } from '../../lib/api';
import { formatDate } from '../../lib/format';
import { cn } from '../../lib/utils';
import { useConfirm } from '../../hooks/useConfirm';
import { Section } from '../ui/Section';
import { Button } from '../ui/Button';
import { Badge } from '../ui/Badge';
import { Notice } from '../ui/Notice';
import { SegmentedControl } from '../ui/SegmentedControl';
import { DataTable, type Column } from '../ui/DataTable';

export interface ApiToken {
  id: string;
  name: string;
  scope: 'read' | 'write';
  created_by: string;
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
  revoked_at: string | null;
}

type Scope = ApiToken['scope'];
type Expiry = '30' | '90' | '365' | 'never';

const tokensKey = ['api-tokens'] as const;

const INPUT = 'h-9 w-full min-w-0 rounded-control border border-line-strong bg-surface px-3 text-sm text-ink focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent';
// The same rule as the backend (handlers.tokenName).
const NAME_RULE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/;

function tokenState(t: ApiToken, now: number): { label: string; tone: 'success' | 'neutral' | 'warning' } {
  if (t.revoked_at) return { label: `Revoked ${formatDate(t.revoked_at)}`, tone: 'neutral' };
  if (t.expires_at && Date.parse(t.expires_at) <= now) return { label: 'Expired', tone: 'warning' };
  return { label: 'Active', tone: 'success' };
}

function NewTokenValue({ name, value, onDone }: { name: string; value: string; onDone: () => void }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);
  const copy = async () => {
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(value);
      setCopied(true);
      toast.success('Copied the token');
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error('Clipboard access denied');
    }
  };
  return (
    <Notice tone="warning" title={`Copy the token "${name}" now: it is not shown again`}>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <code aria-label="New token" className="break-all rounded bg-surface-muted px-2 py-1 font-mono text-[12px] text-ink">{value}</code>
        <Button size="sm" onClick={() => void copy()}>{copied ? 'Copied' : 'Copy token'}</Button>
        <Button size="sm" variant="ghost" onClick={onDone}>Done</Button>
      </div>
      <p className="mt-2 text-sm">Send it as <code className="font-mono text-[12px]">Authorization: Bearer &lt;token&gt;</code>.</p>
    </Notice>
  );
}

export function ApiTokens() {
  const id = useId();
  const queryClient = useQueryClient();
  const { confirm, dialog } = useConfirm();
  const list = useQuery({ queryKey: tokensKey, queryFn: () => getData<ApiToken[]>('tokens'), retry: false });

  const [name, setName] = useState('');
  const [scope, setScope] = useState<Scope>('read');
  const [expiry, setExpiry] = useState<Expiry>('90');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [created, setCreated] = useState<{ name: string; value: string } | null>(null);

  const trimmed = name.trim();
  const nameInvalid = trimmed !== '' && !NAME_RULE.test(trimmed);

  const create = async (e: FormEvent) => {
    e.preventDefault();
    if (trimmed === '' || nameInvalid || saving) return;
    setSaving(true);
    setError('');
    try {
      const body = expiry === 'never'
        ? { name: trimmed, scope, no_expiry: true }
        : { name: trimmed, scope, expires_in_days: Number(expiry) };
      const res = await api.post('tokens', body);
      const data = (res.data as { data?: { token?: string; name?: string } }).data;
      if (data?.token) setCreated({ name: data.name ?? trimmed, value: data.token });
      setName('');
    } catch (err) {
      setError(`Not created: ${getErrorMessage(err, 'the backend did not answer')}.`);
    } finally {
      setSaving(false);
      void queryClient.invalidateQueries({ queryKey: tokensKey });
    }
  };

  const revoke = async (t: ApiToken) => {
    const ok = await confirm({
      title: `Revoke the token "${t.name}"?`,
      body: 'Whatever uses it is refused from now on. This cannot be undone; create a new token to give access again.',
      confirmLabel: 'Revoke',
      destructive: true,
    });
    if (!ok) return;
    try {
      await api.delete(`tokens/${encodeURIComponent(t.id)}`);
      toast.success(`Revoked "${t.name}"`);
    } catch (err) {
      toast.error(getErrorMessage(err, 'The token was not revoked'));
    } finally {
      void queryClient.invalidateQueries({ queryKey: tokensKey });
    }
  };

  // Expired is judged at the time the list was read, which keeps render pure.
  const now = list.dataUpdatedAt;
  const columns: Column<ApiToken>[] = [
    { id: 'name', header: 'Name', cell: (t) => <span className="font-medium">{t.name}</span> },
    { id: 'scope', header: 'Scope', cell: (t) => <Badge tone={t.scope === 'write' ? 'accent' : 'neutral'}>{t.scope}</Badge> },
    { id: 'state', header: 'State', cell: (t) => { const s = tokenState(t, now); return <Badge tone={s.tone}>{s.label}</Badge>; } },
    { id: 'expires', header: 'Expires', hideOnPhone: true, cell: (t) => (t.expires_at ? formatDate(t.expires_at) : 'Never') },
    { id: 'used', header: 'Last used', hideOnPhone: true, cell: (t) => (t.last_used_at ? formatDate(t.last_used_at) : 'Never') },
    { id: 'created', header: 'Created', hideOnPhone: true, cell: (t) => `${formatDate(t.created_at)}${t.created_by ? ` by ${t.created_by}` : ''}` },
    {
      id: 'actions', header: 'Actions', headerHidden: true, align: 'right',
      cell: (t) => (t.revoked_at ? null : <Button size="sm" variant="danger-outline" onClick={() => void revoke(t)} aria-label={`Revoke ${t.name}`}>Revoke</Button>),
    },
  ];

  return (
    <Section
      level={3}
      title="API tokens"
      description="Scripts and tools sign in with a token instead of the admin password. A read token can only read; a write token can also change settings and lists. Neither can manage tokens, change the password, export or reset the database, or back up and restore the configuration. Each use is in the audit log as token:<name>."
    >
      <div className="flex flex-col gap-4">
        {created && <NewTokenValue name={created.name} value={created.value} onDone={() => setCreated(null)} />}
        <form onSubmit={(e) => void create(e)} className="flex flex-col gap-3">
          <div className="flex flex-wrap items-end gap-3">
            <div className="flex min-w-48 flex-1 flex-col gap-1.5">
              <label htmlFor={`${id}-name`} className="text-sm font-medium text-ink">Name</label>
              <input
                id={`${id}-name`}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. grafana"
                autoComplete="off"
                aria-invalid={nameInvalid || undefined}
                aria-describedby={nameInvalid ? `${id}-name-error` : undefined}
                className={cn(INPUT, nameInvalid && 'border-danger-line')}
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <span className="text-sm font-medium text-ink">Scope</span>
              <SegmentedControl label="Scope" value={scope} onChange={setScope} options={[{ value: 'read', label: 'Read' }, { value: 'write', label: 'Write' }]} />
            </div>
            <div className="flex flex-col gap-1.5">
              <span className="text-sm font-medium text-ink">Expires after</span>
              <SegmentedControl
                label="Expires after"
                value={expiry}
                onChange={setExpiry}
                options={[{ value: '30', label: '30 days' }, { value: '90', label: '90 days' }, { value: '365', label: '1 year' }, { value: 'never', label: 'Never' }]}
              />
            </div>
            <Button type="submit" variant="primary" disabled={trimmed === '' || nameInvalid || saving}>{saving ? 'Creating...' : 'Create token'}</Button>
          </div>
          {nameInvalid && <p id={`${id}-name-error`} className="text-sm text-danger">Letters, digits, spaces, dots, underscores and hyphens, up to 64, starting with a letter or digit.</p>}
          {expiry === 'never' && <p className="text-sm text-ink-muted">A token that never expires works until it is revoked.</p>}
          {error && <p role="alert" className="text-sm text-danger">{error}</p>}
        </form>
        <DataTable
          caption="API tokens"
          columns={columns}
          rows={list.data ?? []}
          rowKey={(t) => t.id}
          loading={list.isPending}
          error={list.isError ? getErrorMessage(list.error, 'The tokens could not be read') : null}
          onRetry={() => void list.refetch()}
          empty={{ title: 'No API tokens', description: 'Create one for each script or tool, so each can be revoked alone.' }}
        />
      </div>
      {dialog}
    </Section>
  );
}
