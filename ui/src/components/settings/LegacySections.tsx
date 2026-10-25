/**
 * The Settings content that part B of the redesign replaces: the controls of
 * the previous single-page Settings, moved under the section that will own
 * them and otherwise unchanged, so nothing is lost before each section is
 * rebuilt. Each block reads and writes the section's form through the same
 * fields it always used (formData, setFormData, handleChange).
 */
import type { ChangeEvent } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../ui/card';
import { Download, Bell, Network } from 'lucide-react';
import toast from 'react-hot-toast';
import { api } from '../../lib/api';
import { Toggle } from '../ui/Toggle';
import { SecretField } from './SecretField';
import { ChangePassword } from './ChangePassword';
import { Maintenance } from './Maintenance';
import type { SecretEdit, SecretState } from '../../lib/secrets';

export interface LegacyForm {
  formData: Record<string, string>;
  setFormData: (update: (prev: Record<string, string>) => Record<string, string>) => void;
  handleChange: (e: ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => void;
  secretProps: (key: string) => { state: SecretState; edit?: SecretEdit; onEdit: (edit: SecretEdit | undefined) => void };
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
