/**
 * Clients and access: who may use the proxy, when, and how fast.
 *
 * Who may connect is read-only: the proxy's client sources are fixed in its
 * configuration generator (acl localnet in proxy/generate_squid_conf.sh)
 * plus GUI_IP_WHITELIST from .env, which this page cannot read. The three
 * toggles each rewrite a file the generator reads; their parameters show
 * only while the toggle is on and are saved with it. The proxy login's
 * credentials also show while some are stored, so they can be removed.
 *
 * Proxy login needs its own username and password (the password is
 * write-only, lib/secrets). The backend writes their bcrypt line to the file
 * the proxy checks; with login on and none set the proxy refuses every
 * client, which this section says before a save and after.
 */
import { Section } from '../../ui/Section';
import { Notice } from '../../ui/Notice';
import { SecretRow, TextField, ToggleRow } from '../fields';
import type { SectionForm } from '../sectionForm';
import type { ProxyAuthStatus } from '../../../lib/queries';
import { PROXY_LOGIN_NO_CREDENTIALS, proxyLoginWithoutCredentials } from '../../../lib/attention';

const PRIVATE_NETWORKS = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7', 'fe80::/10'];

function Code({ children }: { children: string }) {
  return <code className="rounded bg-surface-muted px-1 py-px font-mono text-[12px] text-ink">{children}</code>;
}

/**
 * The one notice the Login block shows, most urgent first: login is on with
 * no credentials now (every client refused), the draft would save that, or
 * the draft turns login on and every device will have to sign in.
 */
function LoginNotice({ running, draft, turningOn }: { running: boolean; draft: boolean; turningOn: boolean }) {
  if (running) {
    return (
      <Notice tone="danger" title={PROXY_LOGIN_NO_CREDENTIALS} className="mt-3">
        Devices get 403 on every request. Set a username and a password and save, or turn proxy login off.
      </Notice>
    );
  }
  if (draft) {
    return (
      <Notice tone="warning" title="Set the proxy username and password before you save" className="mt-3">
        With proxy login on and no credentials the proxy refuses every client, so the save is refused until both are set.
      </Notice>
    );
  }
  if (turningOn) {
    return (
      <Notice tone="warning" title="Every device must sign in after you save" className="mt-3">
        A device set up without a proxy login gets 407 Proxy Authentication Required on every request until its proxy settings
        carry the proxy username and password.
      </Notice>
    );
  }
  return null;
}

export function AccessSection({ form, proxyAuth }: { form: SectionForm; proxyAuth?: ProxyAuthStatus }) {
  const v = form.values;
  const loginOn = v.enable_proxy_auth === 'true';
  const turningAuthOn = loginOn && form.stored.enable_proxy_auth !== 'true';
  const password = form.secretProps('proxy_auth_password');
  const storedCredentials = !!form.stored.proxy_auth_username || password.state !== 'unset';
  // What runs now (the stored settings and the proxy's own record), and what
  // the draft would save.
  const runningWithout = proxyLoginWithoutCredentials(form.stored, { proxy_auth_password: password.state }, proxyAuth);
  const passwordAfterSave = password.edit ? password.edit.kind === 'replace' : password.state !== 'unset';
  const draftWithout = loginOn && (!v.proxy_auth_username || !passwordAfterSave);
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
          help="Every client signs in with the proxy username and password below before it can browse."
        />
        {(loginOn || storedCredentials) && (
          <div className="flex flex-col gap-3">
            <p className="text-sm leading-5 text-ink-muted">
              Devices enter these in their proxy settings. They are not your dashboard login: they only let a device use the
              proxy, and changing the dashboard password does not change them.
            </p>
            <div className="grid gap-4 md:grid-cols-2">
              <TextField
                form={form}
                setting="proxy_auth_username"
                label="Proxy username"
                autoComplete="off"
                hint="Letters, digits and . _ @ + -, up to 64."
              />
              <SecretRow form={form} setting="proxy_auth_password" label="Proxy password" placeholder="At least 12 characters" />
            </div>
          </div>
        )}
        <LoginNotice running={runningWithout} draft={draftWithout} turningOn={turningAuthOn} />
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
