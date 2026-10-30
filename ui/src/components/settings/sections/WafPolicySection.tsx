/**
 * The WAF policy file (WAF_POLICY_FILE): whether the WAF blocks or only logs,
 * the rules and categories left to log only, and the exceptions. Each change
 * is saved at once as a whole new file, with the digest of the version this
 * page read: the backend refuses it (409) when the file changed since, by
 * hand or in another browser, and writes nothing the WAF refuses. Exceptions
 * are added from a WAF block in the access log.
 */
import { useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { Section } from '../../ui/Section';
import { Notice } from '../../ui/Notice';
import { Button } from '../../ui/Button';
import { SegmentedControl } from '../../ui/SegmentedControl';
import { useConfirm } from '../../../hooks/useConfirm';
import { getErrorMessage } from '../../../lib/api';
import { wafCategoryLabel } from '../../../lib/wafCategories';
import {
  exceptionScope,
  fetchWafPolicy,
  putWafPolicy,
  reloadText,
  wafPolicyKey,
  type WafPolicyFile,
} from '../../../lib/wafPolicy';

type Mode = 'block' | 'observe';

function Code({ children }: { children: string }) {
  return <code className="break-all rounded bg-surface-muted px-1 py-px font-mono text-[12px] text-ink">{children}</code>;
}

export function WafPolicySection() {
  const queryClient = useQueryClient();
  const { confirm, dialog } = useConfirm();
  const state = useQuery({ queryKey: wafPolicyKey, queryFn: fetchWafPolicy, retry: false });

  const save = async (next: WafPolicyFile, done: string, failed: string) => {
    if (!state.data) return;
    try {
      const res = await putWafPolicy(next, state.data.sha256);
      toast.success(`${done} ${reloadText(res.waf)}`);
    } catch (err) {
      toast.error(getErrorMessage(err, failed));
    } finally {
      void queryClient.invalidateQueries({ queryKey: wafPolicyKey });
    }
  };

  const body = () => {
    if (state.isPending) return <p className="text-sm text-ink-muted">Reading the policy file...</p>;
    if (state.isError || !state.data) {
      return <Notice tone="warning" title="GET /api/waf/policy failed">{getErrorMessage(state.error, 'The policy could not be read.')}</Notice>;
    }
    const s = state.data;
    const notices = (
      <>
        {s.path_mismatch && <Notice tone="warning" title="The WAF reads another file" className="mb-3">{s.path_mismatch}.</Notice>}
        {s.waf_error && (
          <Notice tone="warning" title="The running WAF could not be asked which policy it applies" className="mb-3">
            {s.waf_error}. Changes cannot be saved until it answers: the WAF checks every new version first.
          </Notice>
        )}
        {s.waf && s.in_force === false && (
          <Notice tone="info" title="The WAF has not applied this file yet" className="mb-3">
            It re-reads the file within 5 seconds.{s.waf.last_error ? ` Its last attempt failed: ${s.waf.last_error}.` : ''}
          </Notice>
        )}
      </>
    );
    if (!s.policy) {
      return (
        <>
          {notices}
          <Notice tone="danger" title="The policy file does not parse">
            {s.file_error}. Fix <Code>{s.path}</Code> by hand, or reset it to an empty policy.
          </Notice>
          <div className="mt-3">
            <Button
              size="sm"
              variant="danger-outline"
              onClick={async () => {
                const ok = await confirm({
                  title: 'Reset the policy file?',
                  body: 'The file is replaced with an empty policy: every exception and log-only rule in it is lost.',
                  confirmLabel: 'Reset',
                  destructive: true,
                });
                if (ok) await save({ version: 1 }, 'The policy file was reset.', 'The policy file was not reset.');
              }}
            >
              Reset to an empty policy
            </Button>
          </div>
        </>
      );
    }
    const p = s.policy;
    const mode: Mode = p.mode === 'observe' ? 'observe' : 'block';
    const exceptions = p.exceptions ?? [];
    const observeRules = p.observe_rules ?? [];
    const observeCats = p.observe_categories ?? [];

    const setMode = async (m: Mode) => {
      if (m === mode) return;
      const ok = await confirm({
        title: m === 'observe' ? 'Log only, block nothing?' : 'Block again?',
        body: m === 'observe'
          ? 'The WAF keeps deciding and records the requests it would have blocked (would_block in the traffic log), but blocks none of them.'
          : 'The WAF blocks what its rules and this policy say again.',
        confirmLabel: m === 'observe' ? 'Log only' : 'Block',
        destructive: m === 'observe',
      });
      if (!ok) return;
      const next: WafPolicyFile = { ...p };
      if (m === 'observe') next.mode = 'observe';
      else delete next.mode;
      await save(next, m === 'observe' ? 'The WAF logs only.' : 'The WAF blocks again.', 'The mode was not changed.');
    };

    const removeAt = async (i: number) => {
      const x = exceptions[i];
      const ok = await confirm({
        title: `Remove the exception for ${x.rule}?`,
        body: `${x.rule} counts again on ${exceptionScope(x)}.`,
        confirmLabel: 'Remove',
        destructive: true,
      });
      if (!ok) return;
      await save({ ...p, exceptions: exceptions.filter((_, j) => j !== i) }, `The exception for ${x.rule} was removed.`, 'The exception was not removed.');
    };

    const removeObserved = async (kind: 'rule' | 'category', key: string) => {
      const ok = await confirm({
        title: `${kind === 'rule' ? key : wafCategoryLabel(key).label} blocks again?`,
        body: 'Its matches add to the score again, and can block.',
        confirmLabel: 'Block again',
      });
      if (!ok) return;
      const next = kind === 'rule'
        ? { ...p, observe_rules: observeRules.filter((r) => r !== key) }
        : { ...p, observe_categories: observeCats.filter((c) => c !== key) };
      await save(next, `${key} blocks again.`, `${key} was not changed.`);
    };

    return (
      <>
        {notices}
        <div className="flex flex-col gap-4 text-sm">
          <div className="flex flex-wrap items-center gap-3">
            <SegmentedControl<Mode>
              label="WAF mode"
              options={[{ value: 'block', label: 'Block' }, { value: 'observe', label: 'Log only' }]}
              value={mode}
              onChange={(m) => void setMode(m)}
              size="sm"
            />
            <span className="text-ink-muted">
              {mode === 'observe' ? 'The WAF blocks nothing and records what it would have blocked.' : 'The WAF blocks.'}
            </span>
          </div>

          <div>
            <h4 className="mb-1.5 font-semibold">Exceptions</h4>
            {exceptions.length === 0 ? (
              <p className="text-ink-muted">None. Add one from a WAF block in the access log: open the request and pick the rule.</p>
            ) : (
              <ul className="flex flex-col divide-y divide-line-subtle rounded-lg border border-line-subtle">
                {exceptions.map((x, i) => (
                  <li key={`${x.rule}|${x.host ?? ''}|${x.path ?? ''}|${x.target ?? ''}`} className="flex flex-wrap items-start justify-between gap-2 px-3 py-2">
                    <div className="min-w-0">
                      <Code>{x.rule}</Code> <span className="text-ink-secondary">on {exceptionScope(x)}</span>
                      {x.comment && <span className="block text-xs text-ink-muted">{x.comment}</span>}
                    </div>
                    <Button size="sm" variant="ghost" onClick={() => void removeAt(i)} aria-label={`Remove the exception for ${x.rule} on ${exceptionScope(x)}`}>
                      Remove
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {(observeRules.length > 0 || observeCats.length > 0) && (
            <div>
              <h4 className="mb-1.5 font-semibold">Logged only</h4>
              <ul className="flex flex-col divide-y divide-line-subtle rounded-lg border border-line-subtle">
                {observeRules.map((r) => (
                  <li key={`r|${r}`} className="flex items-center justify-between gap-2 px-3 py-2">
                    <span><Code>{r}</Code> <span className="text-ink-muted">rule, every host</span></span>
                    <Button size="sm" variant="ghost" onClick={() => void removeObserved('rule', r)} aria-label={`Block again: ${r}`}>Block again</Button>
                  </li>
                ))}
                {observeCats.map((c) => (
                  <li key={`c|${c}`} className="flex items-center justify-between gap-2 px-3 py-2">
                    <span>{wafCategoryLabel(c).label} <span className="text-ink-muted">category, every host</span></span>
                    <Button size="sm" variant="ghost" onClick={() => void removeObserved('category', c)} aria-label={`Block again: ${wafCategoryLabel(c).label}`}>Block again</Button>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <p className="text-xs text-ink-muted">
            Saved at once to <Code>{s.path}</Code>, after the WAF has checked it. The file can also be edited by hand; this page then shows
            the new version and refuses a change made from the old one.
          </p>
        </div>
      </>
    );
  };

  return (
    <Section
      level={3}
      title="WAF policy"
      description="Log-only rules and exceptions for one host, path or argument, without switching off a category or restarting the WAF."
    >
      {body()}
      {dialog}
    </Section>
  );
}
