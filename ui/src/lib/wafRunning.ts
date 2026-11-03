/**
 * What the WAF runs, in words (components/settings/sections/WafRunning):
 * the rows of the list and why the state is not known.
 */
import type { WafCoverage, WafRunning as Running } from '../types';
import { formatCount } from './format';

const ENGINE: Record<string, string> = {
  hybrid: 'SPM rules plus the OWASP Core Rule Set',
  legacy: 'SPM rules only, without the OWASP Core Rule Set',
};

const REGEX: Record<string, string> = { go: "Go's regexp", re2: 'RE2' };

/** Why the WAF's state is not shown, in the words of the status. */
export function wafUnknownReason(status: WafCoverage['status'] | undefined): string {
  switch (status) {
    case 'auth_failed': return 'The WAF refused the backend credential: set INTERNAL_ALERT_TOKEN to the same value on the waf and backend services.';
    case 'unreachable': return 'The backend cannot reach the WAF.';
    case 'error': return 'The WAF answered the backend with an error.';
    default: return 'GET /api/waf/status did not answer.';
  }
}

/** The rows of the list, each a label and what the WAF said. */
export function wafRunningRows(w: WafCoverage, run: Running): [string, string][] {
  const rows: [string, string][] = [
    ['Engine', ENGINE[run.engine] ?? run.engine],
    ['Blocks at', `a score of ${formatCount(run.threshold)} (WAF_BLOCK_THRESHOLD)`],
  ];
  if (w.rules_enabled !== null && w.categories_enabled !== null) {
    const observed = w.categories_observed ? `, ${formatCount(w.categories_observed)} of them only logged` : '';
    rows.push(['Request rules', `${formatCount(w.rules_enabled)} on, in ${formatCount(w.categories_enabled)} categories${observed}`]);
  }
  const regex = REGEX[run.regex_engine] ?? run.regex_engine;
  rows.push(['Regular expressions', run.regex_shadow ? `${regex} decides; the other engine runs beside it and the WAF logs any disagreement` : regex]);
  rows.push(['Heuristics on', formatCount(run.heuristics)]);
  if (run.policy_mode) {
    const mode = run.policy_mode === 'observe' ? 'Log only: blocks nothing' : 'Block';
    const exceptions = `${formatCount(run.policy_exceptions)} ${run.policy_exceptions === 1 ? 'exception' : 'exceptions'}`;
    rows.push(['Policy', `${mode}, ${exceptions}`]);
  }
  return rows;
}
