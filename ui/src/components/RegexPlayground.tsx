/**
 * RegexPlayground: tries a WAF custom pattern against the URLs of recent
 * requests (POST /api/waf/test-rule, TestRule in backend-go). The backend
 * compiles it with Go's regexp, the dialect the WAF uses, so the page does
 * not check it with JavaScript's (which refuses (?i), for one); a pattern the
 * backend refuses shows the backend's message.
 *
 * The WAF compiles each custom pattern with (?i) in front
 * (waf-go/internal/engine/customrules.go), so the test does the same. The
 * backend scans at most 10,000 requests of the period and returns at most 50
 * matches, and the page says so when a limit was reached.
 */
import { useId, useState } from 'react';
import { api, getErrorMessage } from '../lib/api';
import { formatCount } from '../lib/format';
import { Button } from './ui/Button';
import { Notice } from './ui/Notice';

interface TestResult {
  regex: string;
  hours: number;
  scanned: number;
  matched: number;
  examples: string[];
}

const SCAN_LIMIT = 10_000;
const MATCH_LIMIT = 50;
const PERIODS = [
  { hours: 1, label: 'last hour' },
  { hours: 6, label: 'last 6 hours' },
  { hours: 24, label: 'last 24 hours' },
  { hours: 72, label: 'last 3 days' },
  { hours: 168, label: 'last 7 days' },
];

type State =
  | { kind: 'idle' | 'busy' }
  | { kind: 'done'; result: TestResult }
  | { kind: 'failed'; message: string };

const CASE = '(?i)';

export function RegexPlayground() {
  const [pattern, setPattern] = useState('');
  const [hours, setHours] = useState(24);
  const [state, setState] = useState<State>({ kind: 'idle' });
  const id = useId();

  const test = async () => {
    const p = pattern.trim();
    if (!p) return;
    setState({ kind: 'busy' });
    try {
      const res = await api.post('waf/test-rule', { regex: CASE + p, hours });
      const r = res.data?.data as TestResult | undefined;
      if (!r || typeof r.scanned !== 'number') throw new Error('the backend sent no result');
      setState({ kind: 'done', result: r });
    } catch (err) {
      // The message names the pattern as the backend compiled it, with the
      // case flag the page added; the operator typed it without.
      setState({ kind: 'failed', message: getErrorMessage(err, 'the test did not run').split(CASE).join('') });
    }
  };

  let summary = '';
  if (state.kind === 'done') {
    const r = state.result;
    const matched = r.matched >= MATCH_LIMIT ? `at least ${formatCount(MATCH_LIMIT)}` : formatCount(r.matched);
    const scanned = r.scanned >= SCAN_LIMIT ? `${formatCount(r.scanned)} requests (the most one test reads)` : `${r.scanned === 1 ? '1 request' : `${formatCount(r.scanned)} requests`}`;
    const period = PERIODS.find((x) => x.hours === r.hours)?.label ?? `last ${r.hours} hours`;
    summary = r.scanned === 0
      ? `No request in the ${period} to test against.`
      : `Matches ${matched} of ${scanned} in the ${period}.`;
  }

  return (
    <div className="flex flex-col gap-3">
      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(e) => { e.preventDefault(); void test(); }}
      >
        <div className="flex min-w-0 flex-[1_1_240px] flex-col gap-1.5">
          <label htmlFor={`${id}-pattern`} className="text-sm font-medium text-ink">Pattern</label>
          <input
            id={`${id}-pattern`}
            value={pattern}
            onChange={(e) => setPattern(e.target.value)}
            placeholder="\.torrent$"
            spellCheck={false}
            maxLength={1020}
            aria-describedby={`${id}-hint`}
            className="h-9 w-full min-w-0 rounded-control border border-line-strong bg-surface px-3 font-mono text-sm text-ink placeholder:text-ink-subtle focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent"
          />
        </div>
        <div className="flex flex-col gap-1.5">
          <label htmlFor={`${id}-period`} className="text-sm font-medium text-ink">Requests from the</label>
          <select
            id={`${id}-period`}
            value={hours}
            onChange={(e) => setHours(Number(e.target.value))}
            className="h-9 rounded-control border border-line-strong bg-surface px-2 text-sm text-ink focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent"
          >
            {PERIODS.map((p) => <option key={p.hours} value={p.hours}>{p.label}</option>)}
          </select>
        </div>
        <Button type="submit" disabled={state.kind === 'busy' || !pattern.trim()}>
          {state.kind === 'busy' ? 'Testing...' : 'Test'}
        </Button>
      </form>
      <p id={`${id}-hint`} className="text-xs text-ink-muted">
        Go regular expression syntax, as the WAF reads it, matched without regard to case. It is tested against request URLs only and shows
        what the pattern matches, not what the WAF would block.
      </p>
      <div aria-live="polite">
        {state.kind === 'failed' && (
          <Notice tone="danger" title="The pattern was not tested">{state.message}</Notice>
        )}
        {state.kind === 'done' && (
          <div className="flex flex-col gap-2">
            <p role="status" className="text-sm font-medium text-ink">{summary}</p>
            {state.result.examples.length > 0 && (
              <ul aria-label="Matching URLs" className="flex max-h-48 flex-col gap-0.5 overflow-y-auto rounded-control border border-line bg-surface-muted px-3 py-2">
                {state.result.examples.map((url, i) => (
                  <li key={`${i}-${url}`} className="truncate font-mono text-[12px] text-ink-secondary" title={url}>{url}</li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
