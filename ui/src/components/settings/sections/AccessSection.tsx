/**
 * Clients and access: who may use the proxy, when, and how fast.
 *
 * Who may connect is read-only: the proxy's client sources are fixed in its
 * configuration generator (acl localnet in proxy/generate_squid_conf.sh)
 * plus GUI_IP_WHITELIST from .env, which this page cannot read. The three
 * toggles each rewrite a file the generator reads; their parameters show
 * only while the toggle is on and are saved with it.
 */
import { Section } from '../../ui/Section';
import { Notice } from '../../ui/Notice';
import { TextField, ToggleRow } from '../fields';
import type { SectionForm } from '../sectionForm';

const PRIVATE_NETWORKS = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7', 'fe80::/10'];

function Code({ children }: { children: string }) {
  return <code className="rounded bg-surface-muted px-1 py-px font-mono text-[12px] text-ink">{children}</code>;
}

export function AccessSection({ form }: { form: SectionForm }) {
  const v = form.values;
  const turningAuthOn = v.enable_proxy_auth === 'true' && form.stored.enable_proxy_auth !== 'true';
  const turningHoursOn = v.enable_time_restrictions === 'true' && form.stored.enable_time_restrictions !== 'true';
  const hours = v.time_restriction_start && v.time_restriction_end ? `${v.time_restriction_start} to ${v.time_restriction_end}` : null;

  return (
    <div className="flex flex-col gap-4">
      <Section level={3} title="Who may connect" description="Set by the proxy configuration and .env, not here.">
        <p className="text-sm leading-6 text-ink-secondary">
          Devices on private networks can use the proxy:{' '}
          {PRIVATE_NETWORKS.map((n, i) => (
            <span key={n}><Code>{n}</Code>{i < PRIVATE_NETWORKS.length - 1 ? ', ' : '.'}</span>
          ))}{' '}
          Other networks, for example a Tailscale range, are added with <Code>GUI_IP_WHITELIST</Code> in <Code>.env</Code> and
          a proxy restart. This page cannot read <Code>.env</Code>, so it does not show which ones are set.
        </p>
      </Section>

      <Section level={3} title="Login">
        <ToggleRow
          form={form}
          setting="enable_proxy_auth"
          label="Require proxy login"
          help={<>
            Every client signs in before it can browse. The login is <Code>BASIC_AUTH_USERNAME</Code> and <Code>BASIC_AUTH_PASSWORD</Code> from
            {' '}<Code>.env</Code> as they were when the proxy first turned login on, not your dashboard password, and changing the dashboard
            password does not change it.
          </>}
        />
        {turningAuthOn && (
          <Notice tone="warning" title="Every device must sign in after you save" className="mt-3">
            A device set up without a proxy login gets 407 Proxy Authentication Required on every request until its proxy settings carry the .env credential.
          </Notice>
        )}
      </Section>

      <Section level={3} title="Allowed hours">
        <ToggleRow
          form={form}
          setting="enable_time_restrictions"
          label="Limit to a time window"
          help="Outside the window every proxy client is refused, every day of the week. Times follow the proxy container's clock."
        >
          <div className="grid gap-4 sm:grid-cols-2">
            <TextField form={form} setting="time_restriction_start" label="From" type="time" />
            <TextField form={form} setting="time_restriction_end" label="Until" type="time" hint="Must be later than From, on the same day." />
          </div>
        </ToggleRow>
        {turningHoursOn && (
          <Notice tone="warning" title="Clients are refused outside the window after you save" className="mt-3">
            {hours ? `Browsing works from ${hours}, every day.` : 'Set both times first.'}
          </Notice>
        )}
      </Section>

      <Section level={3} title="Bandwidth">
        <ToggleRow
          form={form}
          setting="enable_bandwidth_limits"
          label="Limit bandwidth"
          help="Caps the speed of the whole network and of each client."
        >
          <div className="grid gap-4 sm:grid-cols-2">
            <TextField form={form} setting="bandwidth_limit_mbps" label="Whole network (Mbps)" inputMode="numeric" />
            <TextField form={form} setting="bandwidth_limit_per_user_kbps" label="Each client (kbps)" inputMode="numeric" hint="0 for no per-client limit." />
          </div>
        </ToggleRow>
      </Section>
    </div>
  );
}
