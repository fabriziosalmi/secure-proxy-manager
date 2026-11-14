/**
 * The configuration history's shapes (GET /api/config/snapshots and
 * .../diff, handlers/config_snapshots.go) and what restoring a snapshot would
 * change, in words.
 */
import { formatCount } from './format';

export interface Snapshot {
  id: number;
  created_at: number;
  username: string;
  reason: string;
  current: boolean;
}

export interface SnapshotDiff {
  settings: { key: string; from: string | null; to: string | null; secret?: boolean }[];
  groups_added: string[];
  groups_removed: string[];
  groups_changed: string[];
  waf_policy: { mode_from: string; mode_to: string; exceptions_from: number; exceptions_to: number; observe_rules_from: number; observe_rules_to: number } | null;
  egress_allowlist_added: string[];
  egress_allowlist_removed: string[];
  same: boolean;
}

function shown(v: string | null): string {
  return v === null ? 'not set' : v === '' ? 'empty' : v;
}

/** The lines of what restoring a snapshot would change; empty when nothing. */
export function diffLines(d: SnapshotDiff): string[] {
  const out: string[] = [];
  for (const s of d.settings) {
    out.push(s.secret ? `${s.key}: the secret changes` : `${s.key}: ${shown(s.from)} becomes ${shown(s.to)}`);
  }
  if (d.groups_added.length) out.push(`Client groups that come back: ${d.groups_added.join(', ')}`);
  if (d.groups_removed.length) out.push(`Client groups that go: ${d.groups_removed.join(', ')}`);
  if (d.groups_changed.length) out.push(`Client groups that change: ${d.groups_changed.join(', ')}`);
  if (d.waf_policy) {
    const p = d.waf_policy;
    out.push(`WAF policy: mode ${p.mode_from || 'none'} becomes ${p.mode_to}, ${formatCount(p.exceptions_from)} exceptions become ${formatCount(p.exceptions_to)}, ${formatCount(p.observe_rules_from)} log-only rules become ${formatCount(p.observe_rules_to)}`);
  }
  if (d.egress_allowlist_added.length) out.push(`Default-deny allowlist entries that come back: ${d.egress_allowlist_added.join(', ')}`);
  if (d.egress_allowlist_removed.length) out.push(`Default-deny allowlist entries that go: ${d.egress_allowlist_removed.join(', ')}`);
  return out;
}

