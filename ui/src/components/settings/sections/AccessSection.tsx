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
 * Proxy login checks either its own username and password (the password is
 * write-only, lib/secrets; the backend writes their bcrypt line to the file
 * the proxy checks) or each user's account in an LDAP directory
 * (handlers/proxy_ldap.go). With login on and what it checks against not set
 * the proxy refuses every client, which this section says before a save and
 * after.
 */
import { Section } from '../../ui/Section';
import { Notice } from '../../ui/Notice';
import { ChoiceRow, SecretRow, TextField, ToggleRow } from '../fields';
import type { SectionForm } from '../sectionForm';
import type { ProxyAuthStatus } from '../../../lib/queries';
import { PROXY_LOGIN_NO_CREDENTIALS, proxyLoginWithoutCredentials } from '../../../lib/attention';
import { utcClockIn, viewerZone } from '../../../lib/format';

const PRIVATE_NETWORKS = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7', 'fe80::/10'];

function Code({ children }: { children: string }) {
  return <code className="rounded bg-surface-muted px-1 py-px font-mono text-[12px] text-ink">{children}</code>;
}

/**
 * The one notice the Login block shows, most urgent first: login is on with
 * no credentials now (every client refused), the draft would save that, or
 * the draft turns login on and every device will have to sign in.
 */
function LoginNotice({ running, draft, turningOn, ldap }: { running: boolean; draft: boolean; turningOn: boolean; ldap: boolean }) {
  if (running) {
    return (
      <Notice tone="danger" title={PROXY_LOGIN_NO_CREDENTIALS} className="mt-3">
        {ldap
          ? 'Devices get 403 on every request. Set the directory URL, the search account and its password, and where users are, and save, or turn proxy login off.'
          : 'Devices get 403 on every request. Set a username and a password and save, or turn proxy login off.'}
      </Notice>
    );
  }
  if (draft) {
    return ldap ? (
      <Notice tone="warning" title="Set the directory before you save" className="mt-3">
        With proxy login from LDAP and no directory to ask the proxy refuses every client, so the save is refused until the
        directory URL, the search account and its password, and where users are, are set.
      </Notice>
    ) : (
      <Notice tone="warning" title="Set the proxy username and password before you save" className="mt-3">
        With proxy login on and no credentials the proxy refuses every client, so the save is refused until both are set.
      </Notice>
    );
  }
  if (turningOn) {
    return (
      <Notice tone="warning" title="Every device must sign in after you save" className="mt-3">
        {ldap
          ? 'A device set up without a proxy login gets 407 Proxy Authentication Required on every request until its user signs in with their directory account.'
          : 'A device set up without a proxy login gets 407 Proxy Authentication Required on every request until its proxy settings carry the proxy username and password.'}
      </Notice>
    );
  }
  return null;
}

/** The directory the proxy checks users against, when the source is LDAP. */
function DirectoryFields({ form }: { form: SectionForm }) {
  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm leading-5 text-ink-muted">
        Each user signs in with their own directory account. The proxy searches for it with the search account, then checks the
        password the user typed against the directory; it remembers a sign-in for an hour, so a disabled account stops working
        within the hour.
      </p>
      <div className="grid gap-4 md:grid-cols-2">
        <TextField
          form={form}
          setting="ldap_url"
          label="Directory URL"
          placeholder="e.g. ldaps://dc1.corp.example"
          hint="ldaps:// checks the directory's certificate against the system's roots. ldap:// sends the passwords in clear."
        />
        <TextField
          form={form}
          setting="ldap_user_base_dn"
          label="Users are under"
          placeholder="e.g. ou=people,dc=corp,dc=example"
          hint="The DN users are searched under, subtree included."
        />
        <TextField
          form={form}
          setting="ldap_bind_dn"
          label="Search account"
          autoComplete="off"
          placeholder="e.g. cn=Proxy Bind,ou=Service Accounts,dc=corp,dc=example"
          hint="A DN, or on Active Directory a user principal name such as proxy@corp.example. A read-only account is enough."
        />
        <SecretRow form={form} setting="ldap_bind_password" label="Search account password" placeholder="Type to replace" />
        <TextField
          form={form}
          setting="ldap_user_filter"
          label="User filter"
          hint="%s is the username typed. (uid=%s) for OpenLDAP, (sAMAccountName=%s) for Active Directory."
        />
      </div>
      <div className="grid gap-4 md:grid-cols-3">
        <TextField
          form={form}
          setting="ldap_group"
          label="Only members of"
          placeholder="e.g. proxy-users"
          hint="Optional. Empty lets in every account the filter finds; a member of no such group gets 403."
        />
        <TextField form={form} setting="ldap_group_base_dn" label="Groups are under" placeholder="e.g. ou=groups,dc=corp,dc=example" />
        <TextField
          form={form}
          setting="ldap_group_filter"
          label="Group filter"
          hint="%g is the group, %u the user's DN. (&(cn=%g)(member=%u)) for groupOfNames and Active Directory."
        />
      </div>
    </div>
  );
}

export function AccessSection({ form, proxyAuth }: { form: SectionForm; proxyAuth?: ProxyAuthStatus }) {
  const v = form.values;
  const loginOn = v.enable_proxy_auth === 'true';
  const turningAuthOn = loginOn && form.stored.enable_proxy_auth !== 'true';
  const password = form.secretProps('proxy_auth_password');
  const storedCredentials = !!form.stored.proxy_auth_username || password.state !== 'unset';
  // What runs now (the stored settings and the proxy's own record), and what
  // the draft would save.
  const ldapPassword = form.secretProps('ldap_bind_password');
  const ldap = v.proxy_auth_source === 'ldap';
  const runningWithout = proxyLoginWithoutCredentials(
    form.stored,
    { proxy_auth_password: password.state, ldap_bind_password: ldapPassword.state },
    proxyAuth,
  );
  const passwordAfterSave = password.edit ? password.edit.kind === 'replace' : password.state !== 'unset';
  const ldapPasswordAfterSave = ldapPassword.edit ? ldapPassword.edit.kind === 'replace' : ldapPassword.state !== 'unset';
  const draftWithout = loginOn && (ldap
    ? !v.ldap_url || !v.ldap_bind_dn || !v.ldap_user_base_dn || !ldapPasswordAfterSave
    : !v.proxy_auth_username || !passwordAfterSave);
  const turningHoursOn = v.enable_time_restrictions === 'true' && form.stored.enable_time_restrictions !== 'true';
  const hours = v.time_restriction_start && v.time_restriction_end ? `${v.time_restriction_start} to ${v.time_restriction_end} UTC` : null;
  // The proxy reads the window on its own clock, UTC: the same hours on the
  // viewer's clock, today, unless the viewer is on UTC too.
  const zone = viewerZone();
  const localFrom = zone ? utcClockIn(v.time_restriction_start ?? '', zone) : null;
  const localUntil = zone ? utcClockIn(v.time_restriction_end ?? '', zone) : null;
  const localHours = localFrom && localUntil && (localFrom !== v.time_restriction_start || localUntil !== v.time_restriction_end)
    ? `${localFrom} to ${localUntil}`
    : null;

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
          help="Every client signs in before it can browse: with the proxy username and password below, or with each user's account in an LDAP directory."
        />
        {loginOn && (
          <ChoiceRow
            form={form}
            setting="proxy_auth_source"
            label="Who signs in"
            help="One shared proxy account, or each user with their own account in an LDAP directory such as OpenLDAP or Active Directory."
            options={[{ value: 'local', label: 'Proxy account' }, { value: 'ldap', label: 'LDAP directory' }]}
          />
        )}
        {loginOn && ldap && <DirectoryFields form={form} />}
        {!ldap && (loginOn || storedCredentials) && (
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
        <LoginNotice running={runningWithout} draft={draftWithout} turningOn={turningAuthOn} ldap={ldap} />
      </Section>

      <Section level={3} title="Allowed hours">
        <ToggleRow
          form={form}
          setting="enable_time_restrictions"
          label="Limit to a time window"
          help="Outside the window every proxy client is refused, every day of the week. Times are UTC: the proxy container's clock has no time zone set."
        >
          <div className="grid gap-4 sm:grid-cols-2">
            <TextField form={form} setting="time_restriction_start" label="From (UTC)" type="time" />
            <TextField form={form} setting="time_restriction_end" label="Until (UTC)" type="time" hint="Must be later than From, on the same day." />
          </div>
          {localHours && (
            <p className="mt-2 text-xs text-ink-muted">On this browser&apos;s clock ({zone}) that is {localHours} today; it moves by an hour when daylight saving time changes.</p>
          )}
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
