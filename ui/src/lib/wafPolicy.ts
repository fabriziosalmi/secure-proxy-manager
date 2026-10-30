/**
 * The WAF policy file and the WAF's account of a block, as the backend
 * serves them (backend-go/internal/handlers/waf_policy.go). The file is the
 * one source of truth: the backend writes a new version only after the WAF
 * has accepted it, and a whole-file PUT carries the digest of the version it
 * was edited from, so a change made elsewhere since is refused (409).
 */
import { api, getData } from './api';

/** One block, as the WAF reported it. */
export interface WafEvent {
  event_id: string;
  timestamp: string;
  client_ip: string;
  host: string;
  path: string;
  url: string;
  source: string;
  /** spm: the built-in rules crossed their threshold; crs: the OWASP Core Rule Set did. */
  blocked_by: string;
  score: number;
  crs_score: number;
  /** Every rule behind the decision, the observed ones included. */
  rules: string[];
  /** The rules that added to a score: the ones an exception can take off. Absent from an older backend. */
  scoring_rules?: string[];
  categories: string[];
  /** For a Core Rule Set block, the argument each scoring rule matched, as an exception names it. */
  crs_targets: { rule: string; target: string }[];
}

export interface WafPolicyException {
  rule: string;
  host?: string;
  path?: string;
  target?: string;
  comment?: string;
}

export interface WafPolicyFile {
  version: number;
  mode?: string;
  observe_rules?: string[];
  observe_categories?: string[];
  exceptions?: WafPolicyException[];
}

/** GET /api/waf/policy. */
export interface WafPolicyState {
  path: string;
  exists: boolean;
  /** The digest a PUT must send back; "" when there is no file. */
  sha256: string;
  /** null when the file does not parse (file_error says why). */
  policy: WafPolicyFile | null;
  file_error?: string;
  /** The policy the WAF has in force; null when the WAF cannot be read (waf_error). */
  waf: { mode?: string; exceptions?: number; sha256?: string; loaded_at?: string; last_error?: string } | null;
  waf_error?: string;
  /** Whether the WAF runs this file now; it re-reads the file within 5 seconds. */
  in_force?: boolean;
  path_mismatch?: string;
}

/** What the WAF did with a written policy. */
export interface WafReload {
  reloaded: boolean;
  detail?: string;
}

export interface WafPolicyWrite {
  added?: boolean;
  sha256?: string;
  waf?: WafReload;
}

export const wafPolicyKey = ['waf', 'policy'] as const;

export function fetchWafEvent(id: string): Promise<WafEvent> {
  return getData<WafEvent>(`waf/events/${encodeURIComponent(id)}`);
}

export function fetchWafPolicy(): Promise<WafPolicyState> {
  return getData<WafPolicyState>('waf/policy');
}

export function addWafException(e: WafPolicyException): Promise<WafPolicyWrite> {
  return api.post('waf/policy/exceptions', e).then((r) => (r.data?.data ?? {}) as WafPolicyWrite);
}

export function observeWafRule(rule: string): Promise<WafPolicyWrite> {
  return api.post('waf/policy/observe-rules', { rule }).then((r) => (r.data?.data ?? {}) as WafPolicyWrite);
}

export function putWafPolicy(policy: WafPolicyFile, sha256: string): Promise<WafPolicyWrite> {
  return api.put('waf/policy', { policy, sha256 }).then((r) => (r.data?.data ?? {}) as WafPolicyWrite);
}

/** The rules an exception can take off: the scoring ones when the backend says, every rule otherwise. */
export function exceptionRules(e: WafEvent): string[] {
  return e.scoring_rules ?? e.rules;
}

export const isCoreRuleSet = (rule: string) => rule.startsWith('CRS-');

/** The sentence after a write: whether the WAF applies it now. */
export function reloadText(w: WafReload | undefined): string {
  if (!w) return '';
  if (w.reloaded) return 'The WAF applies it now.';
  return `The WAF picks it up within 5 seconds${w.detail ? ` (${w.detail})` : ''}.`;
}

/** An exception in words: "SQLi-015 on shop.example, path /api/, argument ARGS:pwd". */
export function exceptionScope(e: WafPolicyException): string {
  const parts = [
    e.host ? (e.host.startsWith('.') ? `${e.host.slice(1)} and the names under it` : e.host) : 'every host',
    e.path ? `path ${e.path}` : null,
    e.target ? `${e.target}` : null,
  ];
  return parts.filter(Boolean).join(', ');
}
