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
    default: return 'The backend did not answer for the WAF.';
  }
}

/**
 * The Core Rule Set's own anomaly threshold: in the hybrid engine it blocks
 * on its own at this score, apart from WAF_BLOCK_THRESHOLD, which scores the
 * SPM rules. The WAF leaves CRS's default (waf-go/internal/crs).
 */
export const CRS_THRESHOLD = 5;

const count = (n: number, one: string, many: string) => `${formatCount(n)} ${n === 1 ? one : many}`;

/**
 * What only logs and never scores, in words: the enabled categories observed
 * by WAF_OBSERVE_CATEGORIES or the policy, and the single rules the policy
 * observes. Null when nothing does.
 */
export function onlyLogged(w: WafCoverage, run?: Running | null): string | null {
  const parts: string[] = [];
  if (w.categories_observed) parts.push(count(w.categories_observed, 'category', 'categories'));
  if (run?.policy_observe_rules) parts.push(count(run.policy_observe_rules, 'single rule', 'single rules'));
  return parts.length ? `${parts.join(' and ')} only logged` : null;
}

/** The rows of the list, each a label and what the WAF said. */
export function wafRunningRows(w: WafCoverage, run: Running): [string, string][] {
  const rows: [string, string][] = [
    ['Engine', ENGINE[run.engine] ?? run.engine],
    ['SPM rules block at', `a score of ${formatCount(run.threshold)} (WAF_BLOCK_THRESHOLD)`],
  ];
  if (run.engine === 'hybrid') rows.push(['Core Rule Set blocks at', `its own anomaly score of ${CRS_THRESHOLD}`]);
  if (w.rules_enabled !== null && w.categories_enabled !== null) {
    const logged = onlyLogged(w, run);
    rows.push(['Request rules', `${formatCount(w.rules_enabled)} on, in ${formatCount(w.categories_enabled)} categories${logged ? `; ${logged}` : ''}`]);
  }
  const regex = REGEX[run.regex_engine] ?? run.regex_engine;
  rows.push(['Regular expressions', run.regex_shadow ? `${regex} decides; the other engine runs beside it and the WAF logs any disagreement` : regex]);
  rows.push(['Heuristics on', formatCount(run.heuristics)]);
  if (run.policy_mode) {
    const mode = run.policy_mode === 'observe' ? 'Log only: blocks nothing' : 'Block';
    rows.push(['Policy', `${mode}, ${count(run.policy_exceptions, 'exception', 'exceptions')}`]);
  }
  return rows;
}
