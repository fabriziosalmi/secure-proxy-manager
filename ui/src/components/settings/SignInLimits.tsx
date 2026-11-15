/**
 * Sign-in limits (GET /api/security/rate-limits, DELETE .../{ip}): the
 * addresses that failed to sign in within the window, blocked ones first. An
 * address that reaches the limit is refused until the oldest of its counted
 * attempts leaves the window (until); letting it sign in again clears its
 * failed attempts and is in the audit log.
 */
import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api, getErrorMessage } from '../../lib/api';
import { formatSpan, formatWhen } from '../../lib/format';
import { cn } from '../../lib/utils';
import { Section } from '../ui/Section';
import { Button } from '../ui/Button';
import { Badge } from '../ui/Badge';

export interface SignInLimit {
  ip: string;
  attempts: number;
  blocked: boolean;
  /** Unix seconds. */
  last_attempt: number;
  /** Unix seconds; only on a blocked address. */
  until?: number;
}

interface LimitsData {
  rows: SignInLimit[];
  max: number | null;
  windowSeconds: number | null;
}

const LIMITS_KEY = ['security', 'rate-limits'] as const;

function when(unix: number): string {
  return formatWhen(new Date(unix * 1000).toISOString(), { style: 'glance', inSentence: true });
}

type Result = { tone: 'success' | 'danger'; text: string } | null;

export function SignInLimits() {
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState<string | null>(null);
  const [result, setResult] = useState<Result>(null);
  const q = useQuery<LimitsData>({
    queryKey: LIMITS_KEY,
    queryFn: async () => {
      const body = (await api.get('security/rate-limits')).data ?? {};
      return {
        rows: Array.isArray(body.data) ? body.data : [],
        max: typeof body.meta?.max_attempts === 'number' ? body.meta.max_attempts : null,
        windowSeconds: typeof body.meta?.window_seconds === 'number' ? body.meta.window_seconds : null,
      };
    },
    refetchInterval: 30_000,
  });

  const release = async (ip: string) => {
    setBusy(ip);
    try {
      await api.delete(`security/rate-limits/${encodeURIComponent(ip)}`);
      setResult({ tone: 'success', text: `${ip} can sign in again.` });
    } catch (err) {
      setResult({ tone: 'danger', text: `${ip} is still limited: ${getErrorMessage(err, 'the backend did not answer')}.` });
    } finally {
      setBusy(null);
      void queryClient.invalidateQueries({ queryKey: LIMITS_KEY });
    }
  };

  const max = q.data?.max;
  const span = q.data?.windowSeconds ? formatSpan(q.data.windowSeconds) : null;
  const rule = max && span
    ? `An address that fails to sign in ${max} times within ${span} is refused until the oldest of those attempts is ${span} old.`
    : 'An address that fails to sign in too often is refused for a while.';

  return (
    <Section title="Sign-in limits" description={`${rule} Letting an address sign in again clears its failed attempts.`}>
      <div className="flex flex-col gap-3">
        <div aria-live="polite">{result && <p className={cn('text-sm', result.tone === 'success' ? 'text-success' : 'text-danger')}>{result.text}</p>}</div>
        {q.isPending && <p className="text-sm text-ink-muted">Reading the sign-in limits...</p>}
        {q.isError && <p role="alert" className="text-sm text-danger">The sign-in limits could not be read.</p>}
        {q.data && q.data.rows.length === 0 && (
          <p className="text-sm text-ink-muted">{span ? `No address has failed to sign in within the last ${span}.` : 'No address has failed to sign in recently.'}</p>
        )}
        {q.data && q.data.rows.length > 0 && (
          <ul aria-label="Addresses with failed sign-ins, refused first" className="flex flex-col divide-y divide-line-subtle">
            {q.data.rows.map((r) => (
              <li key={r.ip} className="flex flex-wrap items-center gap-3 py-2.5">
                <span className="font-mono text-sm text-ink">{r.ip}</span>
                <span className="text-sm tabular-nums text-ink-secondary">
                  {r.attempts}{max ? ` of ${max}` : ''} failed, the last at {when(r.last_attempt)}
                </span>
                {r.blocked && <Badge tone="warning">{r.until ? `Refused until ${when(r.until)}` : 'Refused'}</Badge>}
                <span className="ml-auto">
                  <Button size="sm" onClick={() => void release(r.ip)} disabled={busy !== null}>
                    {busy === r.ip ? 'Clearing...' : 'Let it sign in again'}
                  </Button>
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Section>
  );
}
