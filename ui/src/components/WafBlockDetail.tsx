/**
 * What the WAF said about one block, in the access log's request detail: the
 * rules behind it and, for each rule that added to the score, the exceptions
 * that would let this request through. The WAF reports the block under the
 * event ID the access log row carries (GET /api/waf/events/{id}); an
 * exception goes to the WAF policy file, which the backend writes only after
 * the WAF has accepted it.
 */
import axios from 'axios';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { Button } from './ui/Button';
import { Notice } from './ui/Notice';
import { useConfirm } from '../hooks/useConfirm';
import { getErrorMessage } from '../lib/api';
import { wafCategoryLabel } from '../lib/wafCategories';
import {
  addWafException,
  exceptionRules,
  exceptionScope,
  fetchWafEvent,
  isCoreRuleSet,
  observeWafRule,
  reloadText,
  wafPolicyKey,
  type WafEvent,
  type WafPolicyException,
} from '../lib/wafPolicy';

function Code({ children }: { children: string }) {
  return <code className="break-all rounded bg-surface-muted px-1 py-px font-mono text-[12px] text-ink">{children}</code>;
}

function blockedByText(e: WafEvent): string {
  if (e.blocked_by === 'crs') return `The OWASP Core Rule Set blocked it, with an anomaly score of ${e.crs_score} (it blocks at 5).`;
  if (e.blocked_by === 'spm') return `The built-in rules blocked it, with a score of ${e.score}.`;
  return `The WAF blocked it, with a score of ${e.score}.`;
}

export function WafBlockDetail({ eventId }: { eventId: string }) {
  const queryClient = useQueryClient();
  const { confirm, dialog } = useConfirm();
  const event = useQuery({
    queryKey: ['waf', 'event', eventId],
    queryFn: () => fetchWafEvent(eventId),
    retry: false,
  });

  if (event.isPending) return <p className="text-sm text-ink-muted">Asking the backend what the WAF reported...</p>;
  if (event.isError || !event.data) {
    const gone = axios.isAxiosError(event.error) && event.error.response?.status === 404;
    return (
      <Notice tone="info" title={gone ? 'The WAF\'s details of this block are not kept' : 'The WAF\'s details of this block could not be read'}>
        {gone
          ? 'They are pruned with the access log, and a block from before this version or one whose alert did not reach the backend has none.'
          : getErrorMessage(event.error, 'GET /api/waf/events failed.')}
      </Notice>
    );
  }
  const e = event.data;
  const rules = exceptionRules(e);

  const add = async (x: WafPolicyException, what: string) => {
    const ok = await confirm({
      title: `Add an exception for ${x.rule}?`,
      body: (
        <div className="flex flex-col gap-2">
          <p>{x.rule} stops counting on {what}. It still runs everywhere else, and every other rule still applies to these requests.</p>
          <p>The exception goes into the WAF policy file, after the WAF has checked it.</p>
        </div>
      ),
      confirmLabel: 'Add exception',
    });
    if (!ok) return;
    try {
      const res = await addWafException({ ...x, comment: `Added from the access log (event ${e.event_id})` });
      if (res.added === false) toast.success('The policy already has this exception.');
      else toast.success(`Exception added for ${x.rule}. ${reloadText(res.waf)}`);
      void queryClient.invalidateQueries({ queryKey: wafPolicyKey });
    } catch (err) {
      toast.error(getErrorMessage(err, `The exception for ${x.rule} was not added.`));
    }
  };

  const observe = async (rule: string) => {
    const ok = await confirm({
      title: `Log ${rule} only, on every host?`,
      body: `${rule} keeps running and its matches are recorded, but it no longer blocks anything, anywhere. An exception for one host, path or argument is narrower.`,
      confirmLabel: 'Log only',
      destructive: true,
    });
    if (!ok) return;
    try {
      const res = await observeWafRule(rule);
      if (res.added === false) toast.success(`${rule} is already logged only.`);
      else toast.success(`${rule} is logged only. ${reloadText(res.waf)}`);
      void queryClient.invalidateQueries({ queryKey: wafPolicyKey });
    } catch (err) {
      toast.error(getErrorMessage(err, `${rule} was not left to log only.`));
    }
  };

  return (
    <div className="flex flex-col gap-3 border-t border-line-subtle pt-4 text-sm">
      <h3 className="text-sm font-semibold">What the WAF matched</h3>
      <p className="text-ink-secondary">{blockedByText(e)}</p>
      {e.categories.length > 0 && (
        <p className="text-ink-secondary">
          Categories: {e.categories.map((c) => wafCategoryLabel(c).label).join(', ')}.
        </p>
      )}
      {rules.length === 0 ? (
        <p className="text-ink-muted">The WAF named no rule that added to the score.</p>
      ) : (
        <ul className="flex flex-col gap-3">
          {rules.map((rule) => {
            const targets = isCoreRuleSet(rule) ? e.crs_targets.filter((t) => t.rule === rule) : [];
            return (
              <li key={rule} className="flex flex-col gap-2 rounded-lg border border-line-subtle p-3">
                <div><Code>{rule}</Code></div>
                <div className="flex flex-wrap gap-2">
                  {e.host && (
                    <Button size="sm" onClick={() => void add({ rule, host: e.host }, `${e.host}`)}>
                      Exception for {e.host}
                    </Button>
                  )}
                  {e.host && e.path && e.path !== '/' && (
                    <Button size="sm" onClick={() => void add({ rule, host: e.host, path: e.path }, exceptionScope({ rule, host: e.host, path: e.path }))}>
                      Only this path
                    </Button>
                  )}
                  {e.host && targets.map((t) => (
                    <Button key={t.target} size="sm" onClick={() => void add({ rule, host: e.host, target: t.target }, `${t.target} on ${e.host}`)}>
                      Only {t.target}
                    </Button>
                  ))}
                  <Button size="sm" variant="ghost" onClick={() => void observe(rule)}>Log only, every host</Button>
                </div>
              </li>
            );
          })}
        </ul>
      )}
      {dialog}
    </div>
  );
}
