/**
 * Filtering: what clients are blocked from reaching. The lists themselves
 * live on Blacklists and Egress allowlist; this section holds the switches
 * that decide how they are used.
 */
import { Link } from 'react-router';
import { Section } from '../../ui/Section';
import { Notice } from '../../ui/Notice';
import { TextField, ToggleRow } from '../fields';
import { formatEgressBreakdown, useEgressSummary } from '../../../lib/queries';
import { formatCount } from '../../../lib/format';
import { extensionPatterns } from '../../../lib/settingsValidation';
import { EGRESS_DENY_HELP, EGRESS_EMPTY_REACH } from '../../../lib/egress';
import type { SectionForm } from '../sectionForm';

function Code({ children }: { children: string }) {
  return <code className="rounded bg-surface-muted px-1 py-px font-mono text-[12px] text-ink">{children}</code>;
}

export function FilteringSection({ form }: { form: SectionForm }) {
  const v = form.values;
  const egress = useEgressSummary();
  const denyOn = v.egress_default_deny === 'true';
  const patterns = extensionPatterns(v.blocked_file_types ?? '');

  let allowlist: string;
  if (egress.isPending) allowlist = 'Reading the egress allowlist...';
  else if (egress.isError || egress.total === null) allowlist = 'The size of the egress allowlist could not be read.';
  else if ((egress.providerCount ?? 0) > 0) allowlist = `The egress allowlist holds ${formatEgressBreakdown(egress.manual ?? 0, egress.providerEntries ?? 0, egress.providerCount ?? 0)}.`;
  else allowlist = egress.total === 1 ? 'The egress allowlist holds 1 entry.' : `The egress allowlist holds ${formatCount(egress.total ?? 0)} entries.`;

  return (
    <div className="flex flex-col gap-4">
      <Section level={3} title="Egress" action={{ label: 'Edit the allowlist', to: '/egress' }}>
        <ToggleRow
          form={form}
          setting="egress_default_deny"
          label="Only allowlisted destinations"
          help={EGRESS_DENY_HELP}
        />
        <p className="mt-3 text-sm text-ink-secondary">{allowlist}</p>
        {denyOn && egress.total === 0 && !form.error('egress_default_deny') && (
          <Notice tone="danger" title="The allowlist is empty" className="mt-3">
            {EGRESS_EMPTY_REACH} <Link to="/egress" className="font-semibold underline">Add destinations</Link> first.
          </Notice>
        )}
        <div className="mt-4">
          <TextField
            form={form}
            setting="egress_provider_refresh_hours"
            label="Refresh provider lists every (hours)"
            inputMode="numeric"
            className="sm:max-w-[240px]"
            hint="From 6 to 168. How often enabled provider lists are fetched and checked against their safety rules."
          />
        </div>
      </Section>

      <Section level={3} title="Downloads">
        <ToggleRow
          form={form}
          setting="enable_content_filtering"
          label="Block risky downloads"
          help="Refuses any URL whose path ends with one of these file extensions, in any letter case, with or without a query string after it."
        >
          <TextField
            form={form}
            setting="blocked_file_types"
            label="Blocked extensions"
            placeholder="exe, msi, bat, ps1"
            hint="Separated by commas."
          />
          {patterns.length > 0 && (
            <p className="text-xs text-ink-muted">
              The proxy matches:{' '}
              {patterns.map((p, i) => <span key={p}><Code>{p}</Code>{i < patterns.length - 1 ? ' ' : ''}</span>)}
            </p>
          )}
        </ToggleRow>
      </Section>

      <Section level={3} title="Search and video">
        <ToggleRow
          form={form}
          setting="enable_safesearch"
          label="SafeSearch"
          help="Forces SafeSearch on Google, Bing and DuckDuckGo, through DNS."
        />
        <ToggleRow
          form={form}
          setting="enable_youtube_restricted"
          label="YouTube restricted mode"
          help="Sends YouTube to its restricted mode, which hides mature videos, through DNS."
        />
      </Section>

      <Section level={3} title="Blocklist refresh">
        <ToggleRow
          form={form}
          setting="auto_refresh_enabled"
          label="Refresh the built-in feeds"
          help="Downloads FireHOL level 1 and IPsum level 1 (IPs) and StevenBlack hosts and the URLhaus filter (domains) again, imports what is new, then reloads DNS."
        >
          <TextField
            form={form}
            setting="auto_refresh_hours"
            label="Every (hours)"
            inputMode="numeric"
            className="sm:max-w-[200px]"
            hint="From 1 to 168. The first refresh runs one interval after the worker picks the setting up."
          />
        </ToggleRow>
      </Section>
    </div>
  );
}
