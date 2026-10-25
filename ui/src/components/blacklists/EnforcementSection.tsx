/**
 * EnforcementSection: what really enforces the list on screen, from recorded
 * state only (GET /api/blacklists/enforcement and the list's own count).
 *
 * - Blocked domains: the DNS sinkhole gets every entry the allowed list does
 *   not take out (db.go writeDnsmasqBlocklist, an exact hosts entry each,
 *   "*." and a leading dot dropped, EnforcedDomain); Squid holds its own copy
 *   only while the proxy's record says so (domain_acl_status.json,
 *   SPM_SQUID_DOMAIN_ACL_MAX).
 * - Blocked and allowed IPs: Squid loads the list after merging overlapping
 *   and adjacent entries (normalize_ip_file); the merged count is the
 *   proxy's record, and "Not reported" when it has written none.
 * - The order of the rules (generate_squid_conf.sh) decides what an allowed
 *   entry can override: the blocked lists are checked first.
 */
import type { ReactNode } from 'react';
import { formatClock, formatCount, formatDate } from '../../lib/format';
import { cn } from '../../lib/utils';
import type { Enforcement, IpAclStatus } from '../../types';
import { Button } from '../ui/Button';
import { Section } from '../ui/Section';
import type { ListDef } from './lists';

function Row({ term, children, tone }: { term: string; children: ReactNode; tone?: 'success' | 'warning' | 'muted' }) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5">
      <dt className="text-ink-muted">{term}</dt>
      <dd className={cn('min-w-0 text-right font-medium tabular-nums [overflow-wrap:anywhere]',
        tone === 'success' && 'text-success', tone === 'warning' && 'text-warning', tone === 'muted' && 'font-normal text-ink-muted')}>
        {children}
      </dd>
    </div>
  );
}

/** When the proxy wrote a record: the time today, the date and time before. */
function recordedAt(epochSeconds: number): string {
  if (!epochSeconds) return 'time not recorded';
  const d = new Date(epochSeconds * 1000);
  const now = new Date();
  const sameDay = d.toDateString() === now.toDateString();
  // formatDate takes a backend timestamp; give it the same moment in UTC.
  const iso = d.toISOString().replace('T', ' ').slice(0, 19);
  return sameDay ? `at ${formatClock(d)}` : `on ${formatDate(iso)} at ${formatClock(d)}`;
}

function SquidIpCopy({ record, file }: { record: IpAclStatus | null | undefined; file: string }) {
  if (!record) {
    return (
      <Row term="Networks Squid loads" tone="muted">
        Not reported: the proxy has not written {file}
      </Row>
    );
  }
  return (
    <>
      <Row term="Networks Squid loads">
        {formatCount(record.networks)}
        <span className="block text-xs font-normal text-ink-muted">
          merged from {formatCount(record.entries)} {record.entries === 1 ? 'entry' : 'entries'}, recorded {recordedAt(record.written_at)}
        </span>
      </Row>
      {record.dropped > 0 && <Row term="Lines Squid could not read" tone="warning">{formatCount(record.dropped)}</Row>}
    </>
  );
}

export interface EnforcementSectionProps {
  list: ListDef;
  /** The list's own count (meta.total), undefined while loading. */
  total?: number;
  data?: Enforcement | null;
  loading: boolean;
  error: boolean;
  onReloadDns?: () => void;
  className?: string;
}

export function EnforcementSection({ list, total, data, loading, error, onReloadDns, className }: EnforcementSectionProps) {
  let body: ReactNode;
  if (loading) {
    body = (
      <>
        <span aria-hidden="true" className="block h-24 rounded-md bg-line-subtle animate-pulse" />
        <span role="status" className="sr-only">Loading how this list is enforced</span>
      </>
    );
  } else if (error || !data) {
    body = <p className="text-sm text-ink-muted">Not reported: blacklists/enforcement did not answer, so what enforces this list is unknown.</p>;
  } else if (list.key === 'blocked-domains') {
    const acl = data.squid_domain_acl;
    let squid: ReactNode;
    let tone: 'success' | 'warning' | 'muted' = 'warning';
    if (!acl) {
      squid = 'Not reported: the proxy has not written domain_acl_status.json';
      tone = 'muted';
    } else if (acl.held) {
      squid = `Its own copy of all ${formatCount(acl.names)} names`;
      tone = 'success';
    } else if (acl.names > acl.limit) {
      squid = `No copy: ${formatCount(acl.names)} names is over its limit of ${formatCount(acl.limit)} (SPM_SQUID_DOMAIN_ACL_MAX)`;
    } else {
      squid = 'No copy: the proxy could not write it, the proxy log says why';
    }
    const left = data.domain_blacklist_on_allowed;
    body = (
      <>
        <dl className="flex flex-col gap-2.5 text-sm">
          <Row term="Entries">{formatCount(total ?? data.domain_blacklist_entries)}</Row>
          {acl && <Row term="Distinct names">{formatCount(acl.names)}</Row>}
          <Row term="DNS sinkhole" tone="success">
            {left > 0 ? `Every entry but the ${formatCount(left)} on Allowed domains` : 'Every entry'}
          </Row>
          <Row term="Proxy (Squid)" tone={tone}>{squid}</Row>
          <Row term="Limit">{formatCount(data.dns_blocklist_limit)} entries (SPM_DNS_BLOCKLIST_MAX_DOMAINS)</Row>
        </dl>
        <p className="text-[13px] leading-5 text-ink-muted">
          A name blocks that exact host, not its subdomains. &quot;*.example.com&quot; and &quot;.example.com&quot; each block example.com itself, in the
          DNS sinkhole and in Squid alike. Distinct names count each name once, in lower case, with &quot;*.&quot; and a leading dot dropped.
        </p>
        {onReloadDns && (
          <div><Button size="sm" onClick={onReloadDns}>Rewrite the DNS list</Button></div>
        )}
      </>
    );
  } else if (list.key === 'blocked-ips') {
    body = (
      <>
        <dl className="flex flex-col gap-2.5 text-sm">
          <Row term="Entries">{total === undefined ? 'Loading' : formatCount(total)}</Row>
          <SquidIpCopy record={data.squid_ip_blacklist} file="ip_blacklist_acl_status.json" />
          <Row term="Proxy (Squid)" tone="success">Refuses every destination in the list</Row>
        </dl>
        <p className="text-[13px] leading-5 text-ink-muted">
          Squid matches the address a request goes to. Overlapping and adjacent entries are merged before Squid loads them; the same addresses
          stay blocked. Squid checks this list before Allowed IPs, so an address on both stays blocked. Private and LAN ranges cannot be added.
        </p>
      </>
    );
  } else if (list.key === 'allowed-ips') {
    body = (
      <>
        <dl className="flex flex-col gap-2.5 text-sm">
          <Row term="Entries">{total === undefined ? 'Loading' : formatCount(total)}</Row>
          <SquidIpCopy record={data.squid_ip_whitelist} file="ip_whitelist_acl_status.json" />
        </dl>
        <p className="text-[13px] leading-5 text-ink-muted">
          Squid lets these destinations through ahead of its direct-IP rule and its final deny. It checks Blocked IPs and Blocked domains
          first, so an entry here does not override them.
        </p>
      </>
    );
  } else {
    const left = data.domain_blacklist_on_allowed;
    body = (
      <>
        <dl className="flex flex-col gap-2.5 text-sm">
          <Row term="Entries">{total === undefined ? 'Loading' : formatCount(total)}</Row>
          <Row term="Blocked entries taken out">{formatCount(left)}</Row>
        </dl>
        <p className="text-[13px] leading-5 text-ink-muted">
          A name here takes the same name off Blocked domains before the lists reach the DNS sinkhole and Squid, however it is written
          there: example.com also takes out *.example.com and .example.com, which block example.com itself. It does not cover subdomains,
          so a leading dot or &quot;*.&quot; is refused here.
        </p>
      </>
    );
  }
  return (
    <Section title="Enforcement" className={className}>
      <div className="flex flex-col gap-3">{body}</div>
    </Section>
  );
}
