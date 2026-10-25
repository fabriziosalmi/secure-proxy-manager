import type { ReasonCount } from '../../types';

// The rules a self-hoster configures, as a sentence names them. Only for the
// sentence about rules that blocked nothing: a rule with a count is always
// shown with the API's label.
const MAIN_RULES: { reason: string; phrase: string }[] = [
  { reason: 'domain_blacklist_dns', phrase: 'the domain blacklist at the DNS sinkhole' },
  { reason: 'domain_blacklist', phrase: 'the domain blacklist at the proxy' },
  { reason: 'ip_blacklist', phrase: 'the IP blacklist' },
  { reason: 'waf', phrase: 'the WAF' },
  { reason: 'direct_ip', phrase: 'the direct-IP rule' },
  { reason: 'egress_policy', phrase: 'the egress policy' },
];

/** "a", "a or b", "a, b or c". */
function orList(items: string[]): string {
  if (items.length <= 1) return items.join('');
  return `${items.slice(0, -1).join(', ')} or ${items[items.length - 1]}`;
}

/** The sentence naming the main rules that blocked nothing, or null when each blocked something. */
export function idleRulesSentence(reasons: readonly ReasonCount[]): string | null {
  const counted = new Set(reasons.filter((r) => r.count > 0).map((r) => r.reason));
  const idle = MAIN_RULES.filter((r) => !counted.has(r.reason)).map((r) => r.phrase);
  if (idle.length === 0) return null;
  return `No client request was blocked in the last 24 hours by ${orList(idle)}.`;
}
