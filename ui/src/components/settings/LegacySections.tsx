/**
 * The Settings content that part B of the redesign replaces: the controls of
 * the previous single-page Settings, moved under the section that will own
 * them and otherwise unchanged, so nothing is lost before each section is
 * rebuilt. Each block reads and writes the section's form through the same
 * fields it always used (formData, setFormData, handleChange).
 */
import type { ChangeEvent } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../ui/card';
import { Download, Shield, Bell, Network } from 'lucide-react';
import toast from 'react-hot-toast';
import { api } from '../../lib/api';
import { Toggle } from '../ui/Toggle';
import { SecretField } from './SecretField';
import { ChangePassword } from './ChangePassword';
import { Maintenance } from './Maintenance';
import { Presets } from './Presets';
import { ServiceStatus } from './ServiceStatus';
import { ClientSetup } from '../ClientSetup';
import type { SecretEdit, SecretState } from '../../lib/secrets';

export interface LegacyForm {
  formData: Record<string, string>;
  setFormData: (update: (prev: Record<string, string>) => Record<string, string>) => void;
  handleChange: (e: ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => void;
  secretProps: (key: string) => { state: SecretState; edit?: SecretEdit; onEdit: (edit: SecretEdit | undefined) => void };
}

export function LegacyOverview({ form }: { form: LegacyForm }) {
  const { formData, setFormData } = form;
  return (
    <div className="space-y-6">
      <ServiceStatus />
      <Presets
        formData={formData}
        onApply={(values) => setFormData(prev => ({ ...prev, ...values }))}
      />
      <ClientSetup />
      <Card>
        <CardHeader>
          <CardTitle>Upstream DNS</CardTitle>
          <CardDescription>Pi-hole or AdGuard Home on the LAN can be the upstream DNS</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Pi-hole / AdGuard Detection */}
          <div className="flex items-center justify-between p-3 border border-border/50 rounded-lg bg-secondary/30">
            <div>
              <p className="text-xs font-medium text-cyan-600 dark:text-cyan-400">DNS Provider Auto-Detect</p>
              <p className="text-[10px] text-muted-foreground">Scan LAN for Pi-hole or AdGuard Home to use as upstream DNS</p>
            </div>
            <button
              type="button"
              onClick={async () => {
                const t = toast.loading('Scanning LAN for DNS providers...');
                try {
                  const res = await api.post('dns/detect', {});
                  const found = res.data?.data?.found || [];
                  if (found.length > 0) {
                    const names = found.map((d: { name: string }) => d.name).join(', ');
                    toast.success(`Found: ${names}. Configure in .env DNS_UPSTREAM_1=${found[0].ip}`, { id: t, duration: 8000 });
                  } else {
                    toast.error('No Pi-hole or AdGuard found on LAN', { id: t });
                  }
                } catch {
                  toast.error('Scan failed. Check network access', { id: t });
                }
              }}
              className="px-3 py-1.5 text-xs font-medium rounded-md bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/20 hover:bg-cyan-500/20 transition-colors shrink-0"
            >
              Scan LAN
            </button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

export function LegacyAccess({ form }: { form: LegacyForm }) {
  const { formData, setFormData, handleChange } = form;
  return (
    <Card>
      <CardHeader className="p-4 pb-2">
        <div className="flex items-center space-x-2">
          <Shield className="w-4 h-4 text-indigo-500" />
          <CardTitle className="text-sm">Access Control</CardTitle>
        </div>
        <CardDescription className="text-xs">Manage who and when can use the proxy</CardDescription>
      </CardHeader>
      <CardContent className="p-4 pt-0">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-2">
          {/* Bandwidth */}
          <div className="flex items-center justify-between p-3 border border-border/50 rounded-lg bg-secondary/30">
            <div>
              <p className="text-xs font-medium">Bandwidth Throttling</p>
              <p className="text-[10px] text-muted-foreground">Delay pools for congestion</p>
            </div>
            <Toggle
              name="enable_bandwidth_limits"
              label="Bandwidth Throttling"
              checked={formData.enable_bandwidth_limits === 'true'}
              onChange={(v) => setFormData(prev => ({ ...prev, enable_bandwidth_limits: v ? 'true' : 'false' }))}
              size="sm"
              className="ml-2"
            />
          </div>
          {/* Time restrictions */}
          <div className="flex items-center justify-between p-3 border border-border/50 rounded-lg bg-secondary/30">
            <div>
              <p className="text-xs font-medium">Time-based Restrictions</p>
              <p className="text-[10px] text-muted-foreground">Limit access to specific hours</p>
            </div>
            <Toggle
              name="enable_time_restrictions"
              label="Time-based Restrictions"
              checked={formData.enable_time_restrictions === 'true'}
              onChange={(v) => setFormData(prev => ({ ...prev, enable_time_restrictions: v ? 'true' : 'false' }))}
              size="sm"
              className="ml-2"
            />
          </div>
          {/* Proxy auth */}
          <div className="flex items-center justify-between p-3 border border-border/50 rounded-lg bg-secondary/30">
            <div>
              <p className="text-xs font-medium">Proxy Authentication</p>
              <p className="text-[10px] text-muted-foreground">Require login to use proxy</p>
            </div>
            <Toggle
              name="enable_proxy_auth"
              label="Proxy Authentication"
              checked={formData.enable_proxy_auth === 'true'}
              onChange={(v) => setFormData(prev => ({ ...prev, enable_proxy_auth: v ? 'true' : 'false' }))}
              size="sm"
              className="ml-2"
            />
          </div>
        </div>
        {/* Expanded settings for enabled toggles */}
        {formData.enable_bandwidth_limits === 'true' && (
          <div className="flex gap-3 mt-3 p-3 border border-border/30 rounded-lg bg-secondary/20">
            <div className="flex-1 space-y-1">
              <label htmlFor="bandwidth_limit_mbps" className="text-[10px] text-muted-foreground">Total (Mbps)</label>
              <input type="number" id="bandwidth_limit_mbps" name="bandwidth_limit_mbps" value={formData.bandwidth_limit_mbps || '10'} onChange={handleChange}
                className="w-full bg-secondary/30 border border-border/50 rounded-lg px-2 py-1 text-xs focus:outline-hidden focus:ring-2 focus:ring-primary/40 transition-all" />
            </div>
            <div className="flex-1 space-y-1">
              <label htmlFor="bandwidth_limit_per_user_kbps" className="text-[10px] text-muted-foreground">Per-User (Kbps)</label>
              <input type="number" id="bandwidth_limit_per_user_kbps" name="bandwidth_limit_per_user_kbps" value={formData.bandwidth_limit_per_user_kbps || '500'} onChange={handleChange}
                className="w-full bg-secondary/30 border border-border/50 rounded-lg px-2 py-1 text-xs focus:outline-hidden focus:ring-2 focus:ring-primary/40 transition-all" />
            </div>
          </div>
        )}
        {formData.enable_time_restrictions === 'true' && (
          <div className="flex gap-3 mt-3 p-3 border border-border/30 rounded-lg bg-secondary/20">
            <div className="flex-1 space-y-1">
              <label htmlFor="time_restriction_start" className="text-[10px] text-muted-foreground">Start</label>
              <input type="time" id="time_restriction_start" name="time_restriction_start" value={formData.time_restriction_start || '09:00'} onChange={handleChange}
                className="w-full bg-secondary/30 border border-border/50 rounded-lg px-2 py-1 text-xs focus:outline-hidden focus:ring-2 focus:ring-primary/40 transition-all" />
            </div>
            <div className="flex-1 space-y-1">
              <label htmlFor="time_restriction_end" className="text-[10px] text-muted-foreground">End</label>
              <input type="time" id="time_restriction_end" name="time_restriction_end" value={formData.time_restriction_end || '17:00'} onChange={handleChange}
                className="w-full bg-secondary/30 border border-border/50 rounded-lg px-2 py-1 text-xs focus:outline-hidden focus:ring-2 focus:ring-primary/40 transition-all" />
            </div>
          </div>
        )}
        {formData.enable_proxy_auth === 'true' && (
          <div className="mt-3 p-3 border border-border/30 rounded-lg bg-secondary/20">
            <label htmlFor="auth_method" className="text-[10px] text-muted-foreground">Auth Method</label>
            <select id="auth_method" name="auth_method" value={formData.auth_method || 'basic'} onChange={handleChange}
              className="w-full mt-1 bg-background border border-border rounded-md px-2 py-1 text-xs focus:outline-hidden focus:ring-1 focus:ring-primary">
              <option value="basic">Basic</option>
              <option value="digest">Digest</option>
            </select>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function LegacyFiltering({ form }: { form: LegacyForm }) {
  const { formData, setFormData, handleChange } = form;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Filtering</CardTitle>
        <CardDescription>Egress, downloads, search, blocklist refresh and DNS helpers</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center justify-between p-4 border border-border/50 rounded-lg bg-secondary/40">
          <div className="space-y-0.5">
            <label className="text-sm font-medium">Default-deny egress</label>
            <p className="text-xs text-muted-foreground">Clients may reach only destinations in the Egress Allowlist; everything else is denied.</p>
          </div>
          <Toggle
            name="egress_default_deny"
            label="Default-deny egress"
            checked={formData.egress_default_deny === 'true'}
            onChange={(v) => setFormData(prev => ({ ...prev, egress_default_deny: v ? 'true' : 'false' }))}
            size="md"
            className="ml-4"
          />
        </div>
        {formData.egress_default_deny === 'true' && (
          <div className="text-xs text-muted-foreground p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-md">
            <p className="font-semibold text-amber-600 dark:text-yellow-400 mb-1">Important:</p>
            <p>With an empty Egress Allowlist, all client traffic is blocked. Add the destinations you allow first. Saving restarts the proxy.</p>
          </div>
        )}
        <label className="text-xs font-medium text-muted-foreground mb-1 block">Security & Filtering</label>
        <div className="grid grid-cols-2 lg:grid-cols-3 gap-2">
          {[
            { name: 'enable_safesearch', label: 'SafeSearch', desc: 'Google/Bing/DDG' },
            { name: 'enable_youtube_restricted', label: 'YouTube Restricted', desc: 'Hide mature content' },
            { name: 'enable_content_filtering', label: 'Content Filtering', desc: 'Block dangerous files' },
          ].map(t => (
            <div key={t.name} className="flex items-center justify-between p-3 border border-border/50 rounded-lg bg-secondary/30">
              <div>
                <p className="text-xs font-medium">{t.label}</p>
                <p className="text-[10px] text-muted-foreground">{t.desc}</p>
              </div>
              <Toggle
                name={t.name}
                label={t.label}
                checked={formData[t.name] === 'true'}
                onChange={(v) => setFormData(prev => ({ ...prev, [t.name]: v ? 'true' : 'false' }))}
                size="sm"
                className="ml-2"
              />
            </div>
          ))}
        </div>
        {formData.enable_content_filtering === 'true' && (
          <div className="mt-3 p-3 border border-border/30 rounded-lg bg-secondary/20">
            <label htmlFor="blocked_file_types" className="text-[10px] text-muted-foreground">Blocked Extensions</label>
            <input type="text" id="blocked_file_types" name="blocked_file_types" value={formData.blocked_file_types || 'exe,bat,cmd,dll,js'} onChange={handleChange}
              placeholder="exe,bat,mp4,zip" className="w-full mt-1 bg-background border border-border rounded-md px-2 py-1 text-xs focus:outline-hidden focus:ring-1 focus:ring-primary" />
          </div>
        )}
        {/* Auto-refresh blocklists */}
        <div className="p-4 border border-border/50 rounded-lg bg-secondary/40">
          <div className="flex items-center justify-between mb-2">
            <div>
              <label className="text-sm font-medium">Auto-Refresh Blocklists</label>
              <p className="text-xs text-muted-foreground">Automatically re-download popular IP and domain blocklists. Deduplicates on import.</p>
            </div>
            <Toggle
              name="auto_refresh_enabled"
              label="Auto-Refresh Blocklists"
              checked={formData.auto_refresh_enabled === 'true'}
              onChange={(v) => setFormData(prev => ({ ...prev, auto_refresh_enabled: v ? 'true' : 'false' }))}
              size="sm"
            />
          </div>
          {formData.auto_refresh_enabled === 'true' && (
            <div className="mt-2 pt-2 border-t border-border/50">
              <label htmlFor="auto_refresh_hours" className="text-xs text-muted-foreground">Refresh Interval (hours)</label>
              <input type="number" id="auto_refresh_hours" name="auto_refresh_hours" value={formData.auto_refresh_hours || '24'} onChange={handleChange}
                min={1} max={168} className="w-full mt-1 bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-hidden focus:ring-1 focus:ring-primary" />
              <p className="text-[10px] text-muted-foreground mt-1">Default: 24h. Lists: Firehol L1, Spamhaus DROP, fabriziosalmi/blacklists.</p>
            </div>
          )}
        </div>
        {/* Essential whitelist */}
        <div className="p-4 border border-border/50 rounded-lg bg-secondary/40">
          <div className="flex items-center justify-between mb-3">
            <div>
              <label className="text-sm font-medium text-emerald-600 dark:text-emerald-400">Essential Domain Whitelist</label>
              <p className="text-xs text-muted-foreground">Domains that should never be blocked by the DNS blackhole. Click to add common services.</p>
            </div>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {[
              { label: 'GitHub', domains: ['github.com', 'raw.githubusercontent.com', 'api.github.com', 'gist.github.com', 'objects.githubusercontent.com'] },
              { label: 'Google', domains: ['google.com', 'www.google.com', 'accounts.google.com', 'apis.google.com', 'fonts.googleapis.com', 'fonts.gstatic.com'] },
              { label: 'Microsoft', domains: ['microsoft.com', 'login.microsoftonline.com', 'graph.microsoft.com', 'outlook.office.com'] },
              { label: 'AI Services', domains: ['openai.com', 'api.openai.com', 'claude.ai', 'api.anthropic.com', 'gemini.google.com', 'bard.google.com'] },
              { label: 'Docker', domains: ['docker.com', 'hub.docker.com', 'registry.docker.io', 'auth.docker.io', 'production.cloudflare.docker.com'] },
              { label: 'CDN/JS', domains: ['cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com', 'npmjs.org', 'registry.npmjs.org'] },
              { label: 'Cloudflare', domains: ['cloudflare.com', '1.1.1.1', 'one.one.one.one', 'dash.cloudflare.com'] },
            ].map((group) => (
              <button
                key={group.label}
                type="button"
                onClick={async () => {
                  const t = toast.loading(`Adding ${group.label} domains...`);
                  const results = await Promise.allSettled(
                    group.domains.map((domain) =>
                      api.post('domain-whitelist', { domain, description: `Essential: ${group.label}` })
                    )
                  );
                  const added = results.filter((r) => r.status === 'fulfilled').length;
                  // 400 = already-whitelisted (these domains are known-good), expected on
                  // a repeat click. Anything else (auth, 5xx, network) is a real failure.
                  const failed = results.filter((r) =>
                    r.status === 'rejected' &&
                    ![400, 409].includes((r.reason as { response?: { status?: number } })?.response?.status ?? 0)
                  ).length;
                  if (failed > 0) {
                    toast.error(`${group.label}: ${added} added, ${failed} failed. Check API/auth`, { id: t });
                  } else {
                    toast.success(`${group.label}: ${added} domains whitelisted`, { id: t });
                  }
                }}
                className="px-2.5 py-1 text-xs font-medium rounded-md bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 transition-colors"
              >
                + {group.label}
              </button>
            ))}
          </div>
          <p className="text-[10px] text-muted-foreground mt-2">After adding, go to Blacklists → Domain Whitelist tab to manage, or click "Reload DNS" to apply.</p>
        </div>
        {/* DoH Blocker */}
        <div className="p-3 border border-border/50 rounded-lg bg-secondary/30">
          <div className="flex items-center justify-between">
            <div>
              <label className="text-xs font-medium text-red-600 dark:text-red-400">Block DNS-over-HTTPS (DoH)</label>
              <p className="text-[10px] text-muted-foreground">Prevent devices from bypassing DNS blackhole via encrypted DNS. Blocks Google DNS, Cloudflare DNS, Quad9, etc.</p>
            </div>
            <button
              type="button"
              onClick={async () => {
                const dohDomains = [
                  'dns.google', 'dns.google.com', 'dns64.dns.google',
                  'cloudflare-dns.com', 'mozilla.cloudflare-dns.com', 'one.one.one.one',
                  'doh.opendns.com', 'dns.quad9.net', 'doh.cleanbrowsing.org',
                  'dns.adguard.com', 'doh.appliedprivacy.net', 'doh.li',
                  'dns.nextdns.io', 'dns.controld.com',
                ];
                const t = toast.loading('Blocking DoH providers...');
                const results = await Promise.allSettled(
                  dohDomains.map((domain) =>
                    api.post('domain-blacklist', { domain, description: 'DoH provider (anti-bypass)' })
                  )
                );
                const added = results.filter((r) => r.status === 'fulfilled').length;
                // 400 = already-blacklisted (known-good list), expected on a repeat click.
                const failed = results.filter((r) =>
                  r.status === 'rejected' &&
                  ![400, 409].includes((r.reason as { response?: { status?: number } })?.response?.status ?? 0)
                ).length;
                try { await api.post('maintenance/reload-dns'); } catch { /* ignore */ }
                if (failed > 0) {
                  toast.error(`DoH: ${added} blocked, ${failed} failed. Check API/auth`, { id: t });
                } else {
                  toast.success(`Blocked ${added} DoH providers + DNS reloaded`, { id: t });
                }
              }}
              className="px-3 py-1.5 text-xs font-medium rounded-md bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20 hover:bg-red-500/20 transition-colors shrink-0"
            >
              Block DoH
            </button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

const handleDownloadCa = async () => {
  try {
    const response = await api.get('security/download-ca', { responseType: 'blob' });
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', 'secure-proxy-ca.pem');
    document.body.appendChild(link);
    link.click();
    link.parentNode?.removeChild(link);
    toast.success("CA Certificate downloaded!");
  } catch {
    toast.error("Failed to download CA certificate. Ensure HTTPS filtering is enabled.");
  }
};

export function LegacyInspection({ form }: { form: LegacyForm }) {
  const { formData, setFormData, handleChange } = form;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Certificates, WAF and security</CardTitle>
        <CardDescription>HTTPS inspection, WAF heuristics and the security toggles</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center justify-between p-4 border border-border/50 rounded-lg bg-secondary/40">
          <div className="space-y-0.5">
            <label className="text-sm font-medium">HTTPS Inspection (SSL Bump)</label>
            <p className="text-xs text-muted-foreground">Intercept HTTPS traffic for WAF, content filtering, and security scanning.</p>
          </div>
          <Toggle
            name="ssl_bump_enabled"
            label="HTTPS Inspection (SSL Bump)"
            checked={formData.ssl_bump_enabled === 'true'}
            onChange={(v) => setFormData(prev => ({ ...prev, ssl_bump_enabled: v ? 'true' : 'false' }))}
            size="md"
            className="ml-4"
          />
        </div>
        {formData.ssl_bump_enabled === 'true' && (
          <div className="text-xs text-muted-foreground p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-md">
            <p className="font-semibold text-amber-600 dark:text-yellow-400 mb-1">Important:</p>
            <p>You must install the Root CA Certificate below on all client devices to avoid security warnings.</p>
          </div>
        )}
        <div className="p-4 border border-border/50 rounded-lg bg-secondary/40">
          <h3 className="text-sm font-medium mb-2">Root CA Certificate</h3>
          <p className="text-xs text-muted-foreground mb-4">
            To prevent security warnings when HTTPS inspection is enabled, you must install this Root CA Certificate on all client devices (Windows, macOS, Linux, iOS, Android) and mark it as trusted.
          </p>
          <button 
            onClick={handleDownloadCa}
            className="flex items-center px-4 py-2 bg-secondary text-secondary-foreground rounded-md text-sm font-medium hover:bg-secondary/80 transition-colors"
          >
            <Download className="w-4 h-4 mr-2" />
            Download CA Certificate (.pem)
          </button>
        </div>
        <div className="text-xs text-muted-foreground p-3 bg-blue-500/10 border border-blue-500/20 rounded-md">
          <p className="font-semibold text-blue-600 dark:text-blue-400 mb-1">Installation Instructions:</p>
          <ul className="list-disc pl-4 space-y-1">
            <li><strong>Windows:</strong> Double-click the file and install to "Trusted Root Certification Authorities".</li>
            <li><strong>macOS:</strong> Open in Keychain Access, select the cert, Get Info, and set "Always Trust".</li>
            <li><strong>Linux (Ubuntu):</strong> Copy to <code>/usr/local/share/ca-certificates/</code> and run <code>update-ca-certificates</code>.</li>
          </ul>
        </div>
        {/* WAF Heuristics toggles */}
        <div className="p-4 border border-border/50 rounded-lg bg-secondary/40">
          <label className="text-sm font-medium mb-2 block">WAF Behavioral Heuristics</label>
          <p className="text-xs text-muted-foreground mb-3">Advanced stateful anomaly detection. Applied to the running WAF immediately on save. No container restart needed.</p>
          <div className="grid grid-cols-2 gap-2">
            {[
              { key: 'waf_h_entropy', label: 'Entropy Detection', desc: 'Block high-entropy payloads (encrypted/compressed = exfiltration)' },
              { key: 'waf_h_beaconing', label: 'C2 Beaconing', desc: 'Detect regular-interval request patterns' },
              { key: 'waf_h_pii', label: 'PII Leak Counter', desc: 'Count emails/CC/SSN in responses' },
              { key: 'waf_h_sharding', label: 'Dest Sharding', desc: 'Block rapid multi-destination access' },
              { key: 'waf_h_ghosting', label: 'Protocol Ghosting', desc: 'Detect SSH/ELF/PE in HTTP body' },
              { key: 'waf_h_sequence', label: 'Sequence Validation', desc: 'Detect impossible request sequences (off by default)' },
            ].map((h) => (
              <div key={h.key} className="flex items-center justify-between p-2 bg-secondary/20 rounded">
                <div>
                  <p className="text-xs font-medium">{h.label}</p>
                  <p className="text-[10px] text-muted-foreground">{h.desc}</p>
                </div>
                <Toggle
                  name={h.key}
                  label={h.label}
                  checked={formData[h.key] !== 'false' && formData[h.key] !== '0'}
                  onChange={(v) => setFormData(prev => ({ ...prev, [h.key]: v ? 'true' : 'false' }))}
                  size="sm"
                  className="ml-2"
                />
              </div>
            ))}
          </div>
        </div>
        <div className="p-4 border border-border/50 rounded-lg bg-secondary/40 space-y-2">
          <label htmlFor="waf_block_threshold" className="text-sm font-medium">WAF Block Threshold</label>
          <input
            type="number"
            id="waf_block_threshold"
            name="waf_block_threshold"
            value={formData.waf_block_threshold || '10'}
            onChange={handleChange}
            min={1} max={100}
            className="w-full bg-secondary/30 border border-border/50 rounded-lg px-3 py-2 text-sm focus:outline-hidden focus:ring-2 focus:ring-primary/40 focus:ring-offset-2 focus:ring-offset-background transition-all"
          />
          <p className="text-[10px] text-muted-foreground">Anomaly score needed to block. Lower = stricter (default: 10).</p>
        </div>
        <div className="flex items-center justify-between p-4 border border-border/50 rounded-lg bg-secondary/40">
          <div className="space-y-0.5">
            <label className="text-sm font-medium">Block Known Malicious IPs</label>
            <p className="text-xs text-muted-foreground">Automatically download and apply community blacklists.</p>
          </div>
          <Toggle
            name="enable_ip_blacklist"
            label="Block Known Malicious IPs"
            checked={formData.enable_ip_blacklist !== 'false'}
            onChange={(v) => setFormData(prev => ({ ...prev, enable_ip_blacklist: v ? 'true' : 'false' }))}
            size="md"
          />
        </div>
        <div className="flex items-center justify-between p-4 border border-border/50 rounded-lg bg-secondary/40">
          <div className="space-y-0.5 w-full">
            <div className="flex items-center justify-between mb-2">
              <div>
                <label className="text-sm font-medium">Outbound WAF (Content Inspection)</label>
                <p className="text-xs text-muted-foreground">Inspect request bodies to block sensitive data leaks and injection attacks.</p>
              </div>
              <Toggle
                name="enable_waf"
                label="Outbound WAF (Content Inspection)"
                checked={formData.enable_waf === 'true'}
                onChange={(v) => setFormData(prev => ({ ...prev, enable_waf: v ? 'true' : 'false' }))}
                size="md"
              />
            </div>
            {formData.enable_waf === 'true' && (
              <div className="mt-2 pt-2 border-t border-border/50">
                <p className="text-xs text-muted-foreground mb-2">
                  Custom WAF Rules (Regex format). One rule per line. Lines starting with # are ignored.
                </p>
                <textarea 
                  name="waf_custom_rules"
                  value={formData.waf_custom_rules || '# Example: block specific keyword\n# \\b(secret_project_x)\\b\n'}
                  onChange={handleChange}
                  rows={4}
                  className="w-full bg-secondary/30 border border-border/50 rounded-lg px-3 py-2 text-sm focus:outline-hidden focus:ring-2 focus:ring-primary/40 focus:ring-offset-2 focus:ring-offset-background transition-all font-mono text-xs"
                />
              </div>
            )}
          </div>
        </div>
        <label className="text-xs font-medium text-muted-foreground mb-1 block">Security</label>
        <div className="grid grid-cols-2 lg:grid-cols-3 gap-2">
          {[
            { name: 'block_direct_ip', label: 'Block Direct IP', desc: 'Prevent DNS bypass' },
          ].map(t => (
            <div key={t.name} className="flex items-center justify-between p-3 border border-border/50 rounded-lg bg-secondary/30">
              <div>
                <p className="text-xs font-medium">{t.label}</p>
                <p className="text-[10px] text-muted-foreground">{t.desc}</p>
              </div>
              <Toggle
                name={t.name}
                label={t.label}
                checked={formData[t.name] === 'true'}
                onChange={(v) => setFormData(prev => ({ ...prev, [t.name]: v ? 'true' : 'false' }))}
                size="sm"
                className="ml-2"
              />
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

export function LegacyAlerts({ form }: { form: LegacyForm }) {
  const { formData, setFormData, secretProps } = form;
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center space-x-2">
          <Bell className="w-5 h-5 text-orange-500" />
          <CardTitle>Notifications & Alerts</CardTitle>
        </div>
        <CardDescription>Configure alerts for critical security events and WAF blocks</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center justify-between p-4 border border-border/50 rounded-lg bg-secondary/40">
          <div className="space-y-0.5 w-full">
            <div className="flex items-center justify-between mb-2">
              <div>
                <label className="text-sm font-medium">Enable Notifications</label>
                <p className="text-xs text-muted-foreground">Receive real-time alerts via your preferred providers.</p>
              </div>
              <Toggle
                name="enable_notifications"
                label="Enable Notifications"
                checked={formData.enable_notifications === 'true'}
                onChange={(v) => setFormData(prev => ({ ...prev, enable_notifications: v ? 'true' : 'false' }))}
                size="md"
              />
            </div>
        
            {formData.enable_notifications === 'true' && (
              <div className="mt-4 pt-4 border-t border-border/50 space-y-4">
                {/* Telegram */}
                <div className="space-y-2">
                  <h4 className="text-sm font-medium text-blue-600 dark:text-blue-400">Telegram Bot</h4>
                  <div className="grid gap-3">
                    <SecretField label="Bot token" placeholder="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11" {...secretProps('telegram_bot_token')} />
                    <SecretField label="Chat ID" placeholder="-1001234567890" {...secretProps('telegram_chat_id')} />
                  </div>
                </div>

                {/* Gotify */}
                <div className="space-y-2">
                  <h4 className="text-sm font-medium text-green-600 dark:text-green-400">Gotify Server</h4>
                  <div className="grid gap-3">
                    <SecretField label="Gotify URL" placeholder="https://gotify.yourdomain.com" {...secretProps('gotify_url')} />
                    <SecretField label="App token" {...secretProps('gotify_token')} />
                  </div>
                </div>

                {/* ntfy.sh */}
                <div className="space-y-2">
                  <h4 className="text-sm font-medium text-cyan-600 dark:text-cyan-400">ntfy.sh (Self-hosted Push)</h4>
                  <div className="grid gap-3">
                    <SecretField label="ntfy server URL" placeholder="https://ntfy.sh" {...secretProps('ntfy_url')} />
                    <SecretField label="ntfy topic" placeholder="proxy-alerts" {...secretProps('ntfy_topic')} />
                  </div>
                </div>

                {/* MS Teams */}
                <div className="space-y-2">
                  <h4 className="text-sm font-medium text-purple-600 dark:text-purple-400">Microsoft Teams</h4>
                  <SecretField label="Teams webhook URL" {...secretProps('teams_webhook_url')} />
                </div>

                {/* Custom Webhook */}
                <div className="space-y-2">
                  <h4 className="text-sm font-medium text-orange-600 dark:text-orange-400">Custom Webhook (JSON)</h4>
                  <SecretField label="Webhook URL" placeholder="https://your-webhook-endpoint.com/receive" {...secretProps('webhook_url')} />
                </div>
              </div>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export function LegacyLogs({ form }: { form: LegacyForm }) {
  const { formData, setFormData, handleChange } = form;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Logs</CardTitle>
        <CardDescription>Log retention and the log view</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center justify-between p-3 border border-border/50 rounded-lg bg-secondary/30">
          <div>
            <p className="text-xs font-medium text-blue-600 dark:text-blue-400">GDPR Mode</p>
            <p className="text-[10px] text-muted-foreground">Anonymize IPs in logs (last octet → x)</p>
          </div>
          <Toggle
            name="gdpr_mode"
            label="GDPR Mode"
            checked={formData.gdpr_mode === 'true'}
            onChange={(v) => setFormData(prev => ({ ...prev, gdpr_mode: v ? 'true' : 'false' }))}
            size="sm"
            className="ml-2"
          />
        </div>
        <div className="p-4 border border-border/50 rounded-lg bg-secondary/40 space-y-2">
          <label htmlFor="log_retention_days" className="text-sm font-medium">Log Retention (days)</label>
          <input
            type="number"
            id="log_retention_days"
            name="log_retention_days"
            value={formData.log_retention_days || '30'}
            onChange={handleChange}
            min={1} max={365}
            className="w-full bg-secondary/30 border border-border/50 rounded-lg px-3 py-2 text-sm focus:outline-hidden focus:ring-2 focus:ring-primary/40 focus:ring-offset-2 focus:ring-offset-background transition-all"
          />
          <p className="text-[10px] text-muted-foreground">Logs older than this are automatically deleted.</p>
        </div>
      </CardContent>
    </Card>
  );
}

export function LegacyAdmin() {
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <ChangePassword />
      <Maintenance />
    </div>
  );
}

export function LegacyEngine({ form }: { form: LegacyForm }) {
  const { formData, setFormData, handleChange } = form;
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center space-x-2">
          <Network className="w-5 h-5 text-primary" />
          <CardTitle>Proxy Configuration</CardTitle>
        </div>
        <CardDescription>Basic networking and port settings for Squid</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <label htmlFor="proxy_port" className="text-sm font-medium">Proxy Port</label>
            <input
              type="number"
              id="proxy_port"
              name="proxy_port"
              value={formData.proxy_port || 3128}
              onChange={handleChange}
              className="w-full bg-secondary/30 border border-border/50 rounded-lg px-3 py-2 text-sm focus:outline-hidden focus:ring-2 focus:ring-primary/40 focus:ring-offset-2 focus:ring-offset-background transition-all"
            />
          </div>
          <div className="space-y-2">
            <label htmlFor="cache_size" className="text-sm font-medium">Cache Size (MB)</label>
            <input
              type="number"
              id="cache_size"
              name="cache_size"
              value={formData.cache_size || 1000}
              onChange={handleChange}
              className="w-full bg-secondary/30 border border-border/50 rounded-lg px-3 py-2 text-sm focus:outline-hidden focus:ring-2 focus:ring-primary/40 focus:ring-offset-2 focus:ring-offset-background transition-all"
            />
          </div>
          <div className="space-y-2">
            <label htmlFor="memory_cache" className="text-sm font-medium">Memory Cache (MB)</label>
            <input
              type="number"
              id="memory_cache"
              name="memory_cache"
              value={formData.memory_cache || 256}
              onChange={handleChange}
              className="w-full bg-secondary/30 border border-border/50 rounded-lg px-3 py-2 text-sm focus:outline-hidden focus:ring-2 focus:ring-primary/40 focus:ring-offset-2 focus:ring-offset-background transition-all"
            />
          </div>
        </div>
        <div className="space-y-2">
          <label htmlFor="allowed_networks" className="text-sm font-medium">Allowed Networks</label>
          <input
            type="text"
            id="allowed_networks"
            name="allowed_networks"
            value={formData.allowed_networks || '10.0.0.0/8 172.16.0.0/12 192.168.0.0/16'}
            onChange={handleChange}
            className="w-full bg-secondary/30 border border-border/50 rounded-lg px-3 py-2 text-sm focus:outline-hidden focus:ring-2 focus:ring-primary/40 focus:ring-offset-2 focus:ring-offset-background transition-all"
          />
          <p className="text-xs text-muted-foreground">Space-separated list of CIDR subnets allowed to use the proxy.</p>
        </div>
        <div className="space-y-2">
          <label htmlFor="extra_ssl_ports" className="text-sm font-medium">Extra SSL/HTTPS Ports</label>
          <input
            type="text"
            id="extra_ssl_ports"
            name="extra_ssl_ports"
            value={formData.extra_ssl_ports || ''}
            onChange={handleChange}
            placeholder="8006 9090 8443"
            className="w-full bg-secondary/30 border border-border/50 rounded-lg px-3 py-2 text-sm focus:outline-hidden focus:ring-2 focus:ring-primary/40 focus:ring-offset-2 focus:ring-offset-background transition-all"
          />
          <p className="text-xs text-muted-foreground">Space-separated ports for HTTPS CONNECT (e.g. Proxmox 8006, Grafana 3000). Requires proxy restart.</p>
        </div>
        {/* Network overlay toggles: compact grid */}
        <label className="text-xs font-medium text-muted-foreground mb-1 block">Network & Overlay</label>
        <div className="grid grid-cols-2 gap-2">
          <div className="flex items-center justify-between p-3 border border-border/50 rounded-lg bg-secondary/30">
            <div>
              <p className="text-xs font-medium text-blue-600 dark:text-blue-400">Tailscale</p>
              <p className="text-[10px] text-muted-foreground">Overlay network access</p>
            </div>
            <Toggle
              name="tailscale_enabled"
              label="Tailscale"
              checked={formData.tailscale_enabled === 'true'}
              onChange={(v) => setFormData(prev => ({ ...prev, tailscale_enabled: v ? 'true' : 'false' }))}
              size="sm"
              className="ml-2"
            />
          </div>
          <div className="flex items-center justify-between p-3 border border-border/50 rounded-lg bg-secondary/30">
            <div>
              <p className="text-xs font-medium text-emerald-600 dark:text-emerald-400">Dynamic DNS</p>
              <p className="text-[10px] text-muted-foreground">Auto-update public IP</p>
            </div>
            <Toggle
              name="ddns_enabled"
              label="Dynamic DNS"
              checked={formData.ddns_enabled === 'true'}
              onChange={(v) => setFormData(prev => ({ ...prev, ddns_enabled: v ? 'true' : 'false' }))}
              size="sm"
              className="ml-2"
            />
          </div>
        </div>
        {/* Tailscale expanded */}
        {formData.tailscale_enabled === 'true' && (
          <div className="flex gap-3 mt-2 p-3 border border-border/30 rounded-lg bg-secondary/20">
            <div className="flex-1 space-y-1">
              <label htmlFor="tailscale_auth_key" className="text-[10px] text-muted-foreground">Auth Key</label>
              <input type="password" id="tailscale_auth_key" name="tailscale_auth_key" value={formData.tailscale_auth_key || ''} onChange={handleChange} placeholder="tskey-auth-..."
                className="w-full bg-secondary/30 border border-border/50 rounded-lg px-2 py-1 text-xs focus:outline-hidden focus:ring-2 focus:ring-primary/40 transition-all" />
            </div>
            <div className="flex-1 space-y-1">
              <label htmlFor="tailscale_hostname" className="text-[10px] text-muted-foreground">Hostname</label>
              <input type="text" id="tailscale_hostname" name="tailscale_hostname" value={formData.tailscale_hostname || 'secure-proxy'} onChange={handleChange}
                className="w-full bg-secondary/30 border border-border/50 rounded-lg px-2 py-1 text-xs focus:outline-hidden focus:ring-2 focus:ring-primary/40 transition-all" />
            </div>
          </div>
        )}
        {/* DDNS expanded */}
        {formData.ddns_enabled === 'true' && (
          <div className="flex gap-3 mt-2 p-3 border border-border/30 rounded-lg bg-secondary/20">
            <div className="flex-1 space-y-1">
              <label htmlFor="ddns_provider" className="text-[10px] text-muted-foreground">Provider</label>
              <select id="ddns_provider" name="ddns_provider" value={formData.ddns_provider || 'cloudflare'} onChange={handleChange}
                className="w-full bg-secondary/30 border border-border/50 rounded-lg px-2 py-1 text-xs focus:outline-hidden focus:ring-2 focus:ring-primary/40 transition-all">
                <option value="cloudflare">Cloudflare</option><option value="duckdns">DuckDNS</option><option value="noip">No-IP</option><option value="custom">Custom</option>
              </select>
            </div>
            <div className="flex-1 space-y-1">
              <label htmlFor="ddns_domain" className="text-[10px] text-muted-foreground">Domain</label>
              <input type="text" id="ddns_domain" name="ddns_domain" value={formData.ddns_domain || ''} onChange={handleChange} placeholder="proxy.example.com"
                className="w-full bg-secondary/30 border border-border/50 rounded-lg px-2 py-1 text-xs focus:outline-hidden focus:ring-2 focus:ring-primary/40 transition-all" />
            </div>
            <div className="flex-1 space-y-1">
              <label htmlFor="ddns_token" className="text-[10px] text-muted-foreground">Token</label>
              <input type="password" id="ddns_token" name="ddns_token" value={formData.ddns_token || ''} onChange={handleChange}
                className="w-full bg-secondary/30 border border-border/50 rounded-lg px-2 py-1 text-xs focus:outline-hidden focus:ring-2 focus:ring-primary/40 transition-all" />
            </div>
          </div>
        )}

        {/* Proxy behavior toggles: compact grid */}
        <label className="text-xs font-medium text-muted-foreground mb-1 block mt-4">Proxy Behavior</label>
        <div className="grid grid-cols-2 gap-2">
          {[
            { name: 'aggressive_caching_enabled', label: 'Aggressive Cache', desc: 'Force static caching' },
            { name: 'enable_offline_mode', label: 'Offline Mode', desc: 'Serve stale cache' },
          ].map(t => (
            <div key={t.name} className="flex items-center justify-between p-3 border border-border/50 rounded-lg bg-secondary/30">
              <div>
                <p className="text-xs font-medium">{t.label}</p>
                <p className="text-[10px] text-muted-foreground">{t.desc}</p>
              </div>
              <Toggle
                name={t.name}
                label={t.label}
                checked={formData[t.name] === 'true'}
                onChange={(v) => setFormData(prev => ({ ...prev, [t.name]: v ? 'true' : 'false' }))}
                size="sm"
                className="ml-2"
              />
            </div>
          ))}
        </div>

        {/* Cache bypass */}
        <div className="mt-3 p-3 border border-border/30 rounded-lg bg-secondary/20">
          <label htmlFor="cache_bypass_domains" className="text-[10px] text-muted-foreground">Cache Bypass Domains (comma-separated)</label>
          <input type="text" id="cache_bypass_domains" name="cache_bypass_domains" value={formData.cache_bypass_domains || ''} onChange={handleChange}
            placeholder="banking.com, api.internal.local"
            className="w-full mt-1 bg-background border border-border rounded-md px-2 py-1 text-xs focus:outline-hidden focus:ring-1 focus:ring-primary" />
        </div>
      </CardContent>
    </Card>
  );
}
