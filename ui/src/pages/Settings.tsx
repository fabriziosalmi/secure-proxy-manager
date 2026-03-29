import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card';
import { useQuery } from '@tanstack/react-query';
import type { SettingRow } from '../types';
import { Save, Download, Shield, Network, Key, Bell } from 'lucide-react';
import { useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import { api } from '../lib/api';
import { z } from 'zod';
import { ChangePassword } from '../components/settings/ChangePassword';
import { Maintenance } from '../components/settings/Maintenance';
import { Presets } from '../components/settings/Presets';
import { ClientSetup } from '../components/ClientSetup';

// Validation schema for settings form data
const settingsSchema = z.object({
  proxy_port: z.string().regex(/^\d+$/, "Port must be a number").refine(val => {
    const port = parseInt(val, 10);
    return port > 0 && port <= 65535;
  }, "Port must be between 1 and 65535").optional(),
  admin_email: z.string().email("Invalid email address").optional().or(z.literal('')),
  enable_siem_forwarding: z.enum(['true', 'false']).optional(),
  siem_host: z.string().optional(),
  siem_port: z.string().regex(/^\d+$/, "Port must be a number").refine(val => {
    const port = parseInt(val, 10);
    return port > 0 && port <= 65535;
  }, "Port must be between 1 and 65535").optional().or(z.literal('')),
  max_cache_size_mb: z.string().regex(/^\d+$/, "Size must be a number").optional(),
  custom_squid_conf: z.string().optional()
}).catchall(z.string());

export function Settings() {
  const { data: settingsData, isLoading: loading, error } = useQuery<SettingRow[]>({
    queryKey: ['settings'],
    queryFn: () => api.get('settings').then(r => r.data.data),
  });
  const [formData, setFormData] = useState<Record<string, string>>({});
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    if (!loading && !error && Array.isArray(settingsData)) {
      // API returns [{setting_name, setting_value}, ...] — convert to {key: value} map
      const map: Record<string, string> = {};
      settingsData.forEach((s) => { map[s.setting_name] = s.setting_value; });
      setFormData(map);
    }
  }, [settingsData, loading, error]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSave = async () => {
    setIsSaving(true);
    
    try {
      // Validate form data before submitting
      settingsSchema.parse(formData);
    } catch (error) {
      if (error instanceof z.ZodError) {
        // Show validation errors to the user
        error.issues.forEach((err: z.ZodIssue) => {
          toast.error(`${err.path.join('.')}: ${err.message}`);
        });
      } else {
        toast.error('Validation failed');
      }
      setIsSaving(false);
      return;
    }

    const loadingToast = toast.loading('Saving settings...');
    // Generate a unique idempotency key for this save operation
    const idempotencyKey = typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    
    try {
      await api.post('settings', formData, {
        headers: {
          'Idempotency-Key': idempotencyKey
        }
      });
      toast.success('Settings saved successfully!', { id: loadingToast });
      
      // Auto reload config after saving
      toast.promise(
        api.post('maintenance/reload-config', {}, {
          headers: {
            'Idempotency-Key': `reload-${idempotencyKey}`
          }
        }),
        {
          loading: 'Applying new configuration to Proxy...',
          success: 'Proxy restarted with new settings!',
          error: 'Failed to restart proxy.',
        }
      );
    } catch (err) {
      toast.error('Failed to save settings', { id: loadingToast });
    } finally {
      setIsSaving(false);
    }
  };


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
    } catch (e) {
      toast.error("Failed to download CA certificate. Ensure HTTPS filtering is enabled.");
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Settings</h1>
          <p className="text-muted-foreground">Configure proxy behavior and security</p>
        </div>
        <button
          onClick={handleSave}
          disabled={isSaving}
          className={`flex items-center px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium transition-colors ${isSaving ? 'opacity-50 cursor-not-allowed' : 'hover:bg-primary/90'}`}
        >
          <Save className="w-4 h-4 mr-2" />
          {isSaving ? 'Saving...' : 'Save Changes'}
        </button>
      </div>

      {/* Quick Setup Presets */}
      <Presets
        formData={formData}
        onApply={(values) => setFormData(prev => ({ ...prev, ...values }))}
      />

      <div className="grid gap-6">
        <Card className="bg-card/50">
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
                <label className="text-sm font-medium">Proxy Port</label>
                <input 
                  type="number" 
                  name="proxy_port"
                  value={formData.proxy_port || 3128}
                  onChange={handleChange}
                  className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">Cache Size (MB)</label>
                <input 
                  type="number" 
                  name="cache_size"
                  value={formData.cache_size || 1000}
                  onChange={handleChange}
                  className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">Memory Cache (MB)</label>
                <input 
                  type="number" 
                  name="cache_mem_size"
                  value={formData.cache_mem_size || 256}
                  onChange={handleChange}
                  className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Allowed Networks</label>
              <input 
                type="text" 
                name="allowed_networks"
                value={formData.allowed_networks || '10.0.0.0/8 172.16.0.0/12 192.168.0.0/16'}
                onChange={handleChange}
                className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
              />
              <p className="text-xs text-muted-foreground">Space-separated list of CIDR subnets allowed to use the proxy.</p>
            </div>
            {/* Network overlay toggles — compact grid */}
            <label className="text-xs font-medium text-muted-foreground mb-1 block">Network & Overlay</label>
            <div className="grid grid-cols-2 gap-2">
              <div className="flex items-center justify-between p-3 border border-border rounded-lg bg-background/30">
                <div>
                  <p className="text-xs font-medium text-blue-400">Tailscale</p>
                  <p className="text-[10px] text-muted-foreground">Overlay network access</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer shrink-0 ml-2">
                  <input type="checkbox" name="enable_tailscale" checked={formData.enable_tailscale === 'true'}
                    onChange={(e) => setFormData({ ...formData, enable_tailscale: e.target.checked ? 'true' : 'false' })} className="sr-only peer" />
                  <div className="w-9 h-5 bg-secondary rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-primary"></div>
                </label>
              </div>
              <div className="flex items-center justify-between p-3 border border-border rounded-lg bg-background/30">
                <div>
                  <p className="text-xs font-medium text-emerald-400">Dynamic DNS</p>
                  <p className="text-[10px] text-muted-foreground">Auto-update public IP</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer shrink-0 ml-2">
                  <input type="checkbox" name="enable_ddns" checked={formData.enable_ddns === 'true'}
                    onChange={(e) => setFormData({ ...formData, enable_ddns: e.target.checked ? 'true' : 'false' })} className="sr-only peer" />
                  <div className="w-9 h-5 bg-secondary rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-primary"></div>
                </label>
              </div>
            </div>
            {/* Tailscale expanded */}
            {formData.enable_tailscale === 'true' && (
              <div className="flex gap-3 mt-2 p-3 border border-border/50 rounded-lg bg-background/20">
                <div className="flex-1 space-y-1">
                  <label className="text-[10px] text-muted-foreground">Auth Key</label>
                  <input type="password" name="tailscale_auth_key" value={formData.tailscale_auth_key || ''} onChange={handleChange} placeholder="tskey-auth-..."
                    className="w-full bg-background border border-border rounded-md px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary" />
                </div>
                <div className="flex-1 space-y-1">
                  <label className="text-[10px] text-muted-foreground">Hostname</label>
                  <input type="text" name="tailscale_hostname" value={formData.tailscale_hostname || 'secure-proxy'} onChange={handleChange}
                    className="w-full bg-background border border-border rounded-md px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary" />
                </div>
              </div>
            )}
            {/* DDNS expanded */}
            {formData.enable_ddns === 'true' && (
              <div className="flex gap-3 mt-2 p-3 border border-border/50 rounded-lg bg-background/20">
                <div className="flex-1 space-y-1">
                  <label className="text-[10px] text-muted-foreground">Provider</label>
                  <select name="ddns_provider" value={formData.ddns_provider || 'cloudflare'} onChange={handleChange}
                    className="w-full bg-background border border-border rounded-md px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary">
                    <option value="cloudflare">Cloudflare</option><option value="duckdns">DuckDNS</option><option value="noip">No-IP</option><option value="custom">Custom</option>
                  </select>
                </div>
                <div className="flex-1 space-y-1">
                  <label className="text-[10px] text-muted-foreground">Domain</label>
                  <input type="text" name="ddns_domain" value={formData.ddns_domain || ''} onChange={handleChange} placeholder="proxy.example.com"
                    className="w-full bg-background border border-border rounded-md px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary" />
                </div>
                <div className="flex-1 space-y-1">
                  <label className="text-[10px] text-muted-foreground">Token</label>
                  <input type="password" name="ddns_token" value={formData.ddns_token || ''} onChange={handleChange}
                    className="w-full bg-background border border-border rounded-md px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary" />
                </div>
              </div>
            )}

            {/* Proxy behavior toggles — compact grid */}
            <label className="text-xs font-medium text-muted-foreground mb-1 block mt-4">Proxy Behavior</label>
            <div className="grid grid-cols-2 gap-2">
              {[
                { name: 'aggressive_caching', label: 'Aggressive Cache', desc: 'Force static caching' },
                { name: 'enable_offline_mode', label: 'Offline Mode', desc: 'Serve stale cache' },
              ].map(t => (
                <div key={t.name} className="flex items-center justify-between p-3 border border-border rounded-lg bg-background/30">
                  <div>
                    <p className="text-xs font-medium">{t.label}</p>
                    <p className="text-[10px] text-muted-foreground">{t.desc}</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer shrink-0 ml-2">
                    <input type="checkbox" name={t.name} checked={formData[t.name] === 'true'}
                      onChange={(e) => setFormData({ ...formData, [t.name]: e.target.checked ? 'true' : 'false' })} className="sr-only peer" />
                    <div className="w-9 h-5 bg-secondary rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-primary"></div>
                  </label>
                </div>
              ))}
            </div>

            {/* Cache bypass */}
            <div className="mt-3 p-3 border border-border/50 rounded-lg bg-background/20">
              <label className="text-[10px] text-muted-foreground">Cache Bypass Domains (comma-separated)</label>
              <input type="text" name="cache_bypass_domains" value={formData.cache_bypass_domains || ''} onChange={handleChange}
                placeholder="banking.com, api.internal.local"
                className="w-full mt-1 bg-background border border-border rounded-md px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary" />
            </div>
          </CardContent>
        </Card>

        {/* Client Setup — how to connect devices */}
        <ClientSetup />

        <Card className="bg-card/50">
          <CardHeader>
            <div className="flex items-center space-x-2">
              <Bell className="w-5 h-5 text-orange-500" />
              <CardTitle>Notifications & Alerts</CardTitle>
            </div>
            <CardDescription>Configure alerts for critical security events and WAF blocks</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between p-4 border border-border rounded-lg bg-background/50">
              <div className="space-y-0.5 w-full">
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <label className="text-sm font-medium">Enable Notifications</label>
                    <p className="text-xs text-muted-foreground">Receive real-time alerts via your preferred providers.</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input 
                      type="checkbox" 
                      name="enable_notifications"
                      checked={formData.enable_notifications === 'true'}
                      onChange={(e) => setFormData({ ...formData, enable_notifications: e.target.checked ? 'true' : 'false' })}
                      className="sr-only peer" 
                    />
                    <div className="w-11 h-6 bg-secondary peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
                  </label>
                </div>
                
                {formData.enable_notifications === 'true' && (
                  <div className="mt-4 pt-4 border-t border-border/50 space-y-4">
                    {/* Telegram */}
                    <div className="space-y-2">
                      <h4 className="text-sm font-medium text-blue-400">Telegram Bot</h4>
                      <div className="grid gap-2">
                        <input 
                          type="text" 
                          name="telegram_bot_token"
                          value={formData.telegram_bot_token || ''}
                          onChange={handleChange}
                          placeholder="Bot Token (e.g. 123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11)"
                          className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                        />
                        <input 
                          type="text" 
                          name="telegram_chat_id"
                          value={formData.telegram_chat_id || ''}
                          onChange={handleChange}
                          placeholder="Chat ID (e.g. -1001234567890)"
                          className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                        />
                      </div>
                    </div>

                    {/* Gotify */}
                    <div className="space-y-2">
                      <h4 className="text-sm font-medium text-green-400">Gotify Server</h4>
                      <div className="grid gap-2">
                        <input 
                          type="text" 
                          name="gotify_url"
                          value={formData.gotify_url || ''}
                          onChange={handleChange}
                          placeholder="Gotify URL (e.g. https://gotify.yourdomain.com)"
                          className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                        />
                        <input 
                          type="text" 
                          name="gotify_token"
                          value={formData.gotify_token || ''}
                          onChange={handleChange}
                          placeholder="App Token"
                          className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                        />
                      </div>
                    </div>

                    {/* ntfy.sh */}
                    <div className="space-y-2">
                      <h4 className="text-sm font-medium text-cyan-400">ntfy.sh (Self-hosted Push)</h4>
                      <div className="grid gap-2">
                        <input
                          type="text"
                          name="ntfy_url"
                          value={formData.ntfy_url || ''}
                          onChange={handleChange}
                          placeholder="Server URL (e.g. https://ntfy.sh or https://ntfy.yourdomain.com)"
                          className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                        />
                        <input
                          type="text"
                          name="ntfy_topic"
                          value={formData.ntfy_topic || ''}
                          onChange={handleChange}
                          placeholder="Topic (e.g. proxy-alerts)"
                          className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                        />
                      </div>
                    </div>

                    {/* MS Teams */}
                    <div className="space-y-2">
                      <h4 className="text-sm font-medium text-purple-400">Microsoft Teams</h4>
                      <input 
                        type="text" 
                        name="teams_webhook_url"
                        value={formData.teams_webhook_url || ''}
                        onChange={handleChange}
                        placeholder="Teams Webhook URL"
                        className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                      />
                    </div>

                    {/* Custom Webhook */}
                    <div className="space-y-2">
                      <h4 className="text-sm font-medium text-orange-400">Custom Webhook (JSON)</h4>
                      <input 
                        type="text" 
                        name="webhook_url"
                        value={formData.webhook_url || ''}
                        onChange={handleChange}
                        placeholder="https://your-webhook-endpoint.com/receive"
                        className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                      />
                    </div>
                  </div>
                )}
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/50">
          <CardHeader>
            <div className="flex items-center space-x-2">
              <Shield className="w-5 h-5 text-cyan-500" />
              <CardTitle>DNS & WAF Intelligence</CardTitle>
            </div>
            <CardDescription>DNS blackhole, WAF heuristics, and essential domain whitelist</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Pi-hole / AdGuard Detection */}
            <div className="flex items-center justify-between p-3 border border-border rounded-lg bg-background/30">
              <div>
                <p className="text-xs font-medium text-cyan-400">DNS Provider Auto-Detect</p>
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
                    toast.error('Scan failed — check network access', { id: t });
                  }
                }}
                className="px-3 py-1.5 text-xs font-medium rounded-md bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 hover:bg-cyan-500/20 transition-colors shrink-0"
              >
                Scan LAN
              </button>
            </div>

            {/* Essential whitelist */}
            <div className="p-4 border border-border rounded-lg bg-background/50">
              <div className="flex items-center justify-between mb-3">
                <div>
                  <label className="text-sm font-medium text-emerald-400">Essential Domain Whitelist</label>
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
                      let added = 0;
                      for (const domain of group.domains) {
                        try {
                          await api.post('domain-whitelist', { domain, description: `Essential: ${group.label}` });
                          added++;
                        } catch { /* already exists */ }
                      }
                      toast.success(`${group.label}: ${added} domains whitelisted`, { id: t });
                    }}
                    className="px-2.5 py-1 text-xs font-medium rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 transition-colors"
                  >
                    + {group.label}
                  </button>
                ))}
              </div>
              <p className="text-[10px] text-muted-foreground mt-2">After adding, go to Blacklists → Domain Whitelist tab to manage, or click "Reload DNS" to apply.</p>
            </div>

            {/* GDPR + DoH — compact row */}
            <div className="grid grid-cols-2 gap-2">
              <div className="flex items-center justify-between p-3 border border-border rounded-lg bg-background/30">
                <div>
                  <p className="text-xs font-medium text-blue-400">GDPR Mode</p>
                  <p className="text-[10px] text-muted-foreground">Anonymize IPs in logs (last octet → x)</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer shrink-0 ml-2">
                  <input type="checkbox" name="gdpr_mode" checked={formData.gdpr_mode === 'true'}
                    onChange={(e) => setFormData({ ...formData, gdpr_mode: e.target.checked ? 'true' : 'false' })}
                    className="sr-only peer" />
                  <div className="w-9 h-5 bg-secondary rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-primary"></div>
                </label>
              </div>

            {/* DoH Blocker */}
            <div className="p-3 border border-border rounded-lg bg-background/30">
              <div className="flex items-center justify-between">
                <div>
                  <label className="text-xs font-medium text-red-400">Block DNS-over-HTTPS (DoH)</label>
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
                    let added = 0;
                    for (const domain of dohDomains) {
                      try {
                        await api.post('domain-blacklist', { domain, description: 'DoH provider (anti-bypass)' });
                        added++;
                      } catch { /* already exists */ }
                    }
                    try { await api.post('maintenance/reload-dns'); } catch { /* ignore */ }
                    toast.success(`Blocked ${added} DoH providers + DNS reloaded`, { id: t });
                  }}
                  className="px-3 py-1.5 text-xs font-medium rounded-md bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 transition-colors shrink-0"
                >
                  Block DoH
                </button>
              </div>
            </div>
            </div>

            {/* Log retention */}
            <div className="grid grid-cols-2 gap-4">
              <div className="p-4 border border-border rounded-lg bg-background/50 space-y-2">
                <label className="text-sm font-medium">Log Retention (days)</label>
                <input
                  type="number"
                  name="log_retention_days"
                  value={formData.log_retention_days || '30'}
                  onChange={handleChange}
                  min={1} max={365}
                  className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                />
                <p className="text-[10px] text-muted-foreground">Logs older than this are automatically deleted.</p>
              </div>
              <div className="p-4 border border-border rounded-lg bg-background/50 space-y-2">
                <label className="text-sm font-medium">WAF Block Threshold</label>
                <input
                  type="number"
                  name="waf_block_threshold"
                  value={formData.waf_block_threshold || '10'}
                  onChange={handleChange}
                  min={1} max={100}
                  className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                />
                <p className="text-[10px] text-muted-foreground">Anomaly score needed to block. Lower = stricter (default: 10).</p>
              </div>
            </div>

            {/* Auto-refresh blocklists */}
            <div className="p-4 border border-border rounded-lg bg-background/50">
              <div className="flex items-center justify-between mb-2">
                <div>
                  <label className="text-sm font-medium">Auto-Refresh Blocklists</label>
                  <p className="text-xs text-muted-foreground">Automatically re-download popular IP and domain blocklists. Deduplicates on import.</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input type="checkbox" name="auto_refresh_enabled" checked={formData.auto_refresh_enabled === 'true'}
                    onChange={(e) => setFormData({ ...formData, auto_refresh_enabled: e.target.checked ? 'true' : 'false' })}
                    className="sr-only peer" />
                  <div className="w-9 h-5 bg-secondary rounded-full peer peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-primary"></div>
                </label>
              </div>
              {formData.auto_refresh_enabled === 'true' && (
                <div className="mt-2 pt-2 border-t border-border/50">
                  <label className="text-xs text-muted-foreground">Refresh Interval (hours)</label>
                  <input type="number" name="auto_refresh_hours" value={formData.auto_refresh_hours || '24'} onChange={handleChange}
                    min={1} max={168} className="w-full mt-1 bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary" />
                  <p className="text-[10px] text-muted-foreground mt-1">Default: 24h. Lists: Firehol L1, Spamhaus DROP, fabriziosalmi/blacklists.</p>
                </div>
              )}
            </div>

            {/* WAF Heuristics toggles */}
            <div className="p-4 border border-border rounded-lg bg-background/50">
              <label className="text-sm font-medium mb-2 block">WAF Behavioral Heuristics</label>
              <p className="text-xs text-muted-foreground mb-3">Advanced stateful anomaly detection. Requires container restart to apply.</p>
              <div className="grid grid-cols-2 gap-2">
                {[
                  { key: 'waf_h_entropy', label: 'Entropy Detection', desc: 'Block high-entropy payloads (encrypted/compressed = exfiltration)' },
                  { key: 'waf_h_beaconing', label: 'C2 Beaconing', desc: 'Detect regular-interval request patterns' },
                  { key: 'waf_h_pii', label: 'PII Leak Counter', desc: 'Count emails/CC/SSN in responses' },
                  { key: 'waf_h_sharding', label: 'Dest Sharding', desc: 'Block rapid multi-destination access' },
                  { key: 'waf_h_ghosting', label: 'Protocol Ghosting', desc: 'Detect SSH/ELF/PE in HTTP body' },
                  { key: 'waf_h_morphing', label: 'Header Morphing', desc: 'Detect header order changes (noisy)' },
                ].map((h) => (
                  <div key={h.key} className="flex items-center justify-between p-2 bg-secondary/20 rounded">
                    <div>
                      <p className="text-xs font-medium">{h.label}</p>
                      <p className="text-[10px] text-muted-foreground">{h.desc}</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer shrink-0 ml-2">
                      <input type="checkbox" name={h.key} checked={formData[h.key] !== 'false' && formData[h.key] !== '0'}
                        onChange={(e) => setFormData({ ...formData, [h.key]: e.target.checked ? 'true' : 'false' })}
                        className="sr-only peer" />
                      <div className="w-9 h-5 bg-secondary rounded-full peer peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-primary"></div>
                    </label>
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/50">
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
              <div className="flex items-center justify-between p-3 border border-border rounded-lg bg-background/30">
                <div>
                  <p className="text-xs font-medium">Bandwidth Throttling</p>
                  <p className="text-[10px] text-muted-foreground">Delay pools for congestion</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer shrink-0 ml-2">
                  <input type="checkbox" name="enable_bandwidth_limits" checked={formData.enable_bandwidth_limits === 'true'}
                    onChange={(e) => setFormData({ ...formData, enable_bandwidth_limits: e.target.checked ? 'true' : 'false' })}
                    className="sr-only peer" />
                  <div className="w-9 h-5 bg-secondary rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-primary"></div>
                </label>
              </div>
              {/* Time restrictions */}
              <div className="flex items-center justify-between p-3 border border-border rounded-lg bg-background/30">
                <div>
                  <p className="text-xs font-medium">Time-based Restrictions</p>
                  <p className="text-[10px] text-muted-foreground">Limit access to specific hours</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer shrink-0 ml-2">
                  <input type="checkbox" name="enable_time_restrictions" checked={formData.enable_time_restrictions === 'true'}
                    onChange={(e) => setFormData({ ...formData, enable_time_restrictions: e.target.checked ? 'true' : 'false' })}
                    className="sr-only peer" />
                  <div className="w-9 h-5 bg-secondary rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-primary"></div>
                </label>
              </div>
              {/* Proxy auth */}
              <div className="flex items-center justify-between p-3 border border-border rounded-lg bg-background/30">
                <div>
                  <p className="text-xs font-medium">Proxy Authentication</p>
                  <p className="text-[10px] text-muted-foreground">Require login to use proxy</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer shrink-0 ml-2">
                  <input type="checkbox" name="enable_proxy_auth" checked={formData.enable_proxy_auth === 'true'}
                    onChange={(e) => setFormData({ ...formData, enable_proxy_auth: e.target.checked ? 'true' : 'false' })}
                    className="sr-only peer" />
                  <div className="w-9 h-5 bg-secondary rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-primary"></div>
                </label>
              </div>
            </div>
            {/* Expanded settings for enabled toggles */}
            {formData.enable_bandwidth_limits === 'true' && (
              <div className="flex gap-3 mt-3 p-3 border border-border/50 rounded-lg bg-background/20">
                <div className="flex-1 space-y-1">
                  <label className="text-[10px] text-muted-foreground">Total (Mbps)</label>
                  <input type="number" name="bandwidth_limit_mbps" value={formData.bandwidth_limit_mbps || '10'} onChange={handleChange}
                    className="w-full bg-background border border-border rounded-md px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary" />
                </div>
                <div className="flex-1 space-y-1">
                  <label className="text-[10px] text-muted-foreground">Per-User (Kbps)</label>
                  <input type="number" name="bandwidth_limit_per_user_kbps" value={formData.bandwidth_limit_per_user_kbps || '500'} onChange={handleChange}
                    className="w-full bg-background border border-border rounded-md px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary" />
                </div>
              </div>
            )}
            {formData.enable_time_restrictions === 'true' && (
              <div className="flex gap-3 mt-3 p-3 border border-border/50 rounded-lg bg-background/20">
                <div className="flex-1 space-y-1">
                  <label className="text-[10px] text-muted-foreground">Start</label>
                  <input type="time" name="time_restriction_start" value={formData.time_restriction_start || '09:00'} onChange={handleChange}
                    className="w-full bg-background border border-border rounded-md px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary" />
                </div>
                <div className="flex-1 space-y-1">
                  <label className="text-[10px] text-muted-foreground">End</label>
                  <input type="time" name="time_restriction_end" value={formData.time_restriction_end || '17:00'} onChange={handleChange}
                    className="w-full bg-background border border-border rounded-md px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary" />
                </div>
              </div>
            )}
            {formData.enable_proxy_auth === 'true' && (
              <div className="mt-3 p-3 border border-border/50 rounded-lg bg-background/20">
                <label className="text-[10px] text-muted-foreground">Auth Method</label>
                <select name="auth_method" value={formData.auth_method || 'basic'} onChange={handleChange}
                  className="w-full mt-1 bg-background border border-border rounded-md px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary">
                  <option value="basic">Basic</option>
                  <option value="digest">Digest</option>
                </select>
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="bg-card/50">
          <CardHeader>
            <div className="flex items-center space-x-2">
              <Key className="w-5 h-5 text-yellow-500" />
              <CardTitle>Certificates & HTTPS</CardTitle>
            </div>
            <CardDescription>Manage SSL/TLS certificates for HTTPS Inspection</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between p-4 border border-border rounded-lg bg-background/50">
              <div className="space-y-0.5">
                <label className="text-sm font-medium">HTTPS Inspection (SSL Bump)</label>
                <p className="text-xs text-muted-foreground">Intercept HTTPS traffic for WAF, content filtering, and security scanning.</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer shrink-0 ml-4">
                <input type="checkbox" name="ssl_bump_enabled" checked={formData.ssl_bump_enabled === 'true'}
                  onChange={(e) => setFormData({ ...formData, ssl_bump_enabled: e.target.checked ? 'true' : 'false' })} className="sr-only peer" />
                <div className="w-11 h-6 bg-secondary peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
              </label>
            </div>
            {formData.ssl_bump_enabled === 'true' && (
              <div className="text-xs text-muted-foreground p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-md">
                <p className="font-semibold text-yellow-400 mb-1">Important:</p>
                <p>You must install the Root CA Certificate below on all client devices to avoid security warnings.</p>
              </div>
            )}
            <div className="p-4 border border-border rounded-lg bg-background/50">
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
              <p className="font-semibold text-blue-400 mb-1">Installation Instructions:</p>
              <ul className="list-disc pl-4 space-y-1">
                <li><strong>Windows:</strong> Double-click the file and install to "Trusted Root Certification Authorities".</li>
                <li><strong>macOS:</strong> Open in Keychain Access, select the cert, Get Info, and set "Always Trust".</li>
                <li><strong>Linux (Ubuntu):</strong> Copy to <code>/usr/local/share/ca-certificates/</code> and run <code>update-ca-certificates</code>.</li>
              </ul>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/50">
          <CardHeader>
            <div className="flex items-center space-x-2">
              <Shield className="w-5 h-5 text-emerald-500" />
              <CardTitle>Security</CardTitle>
            </div>
            <CardDescription>Advanced protection mechanisms</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between p-4 border border-border rounded-lg bg-background/50">
              <div className="space-y-0.5">
                <label className="text-sm font-medium">Block Known Malicious IPs</label>
                <p className="text-xs text-muted-foreground">Automatically download and apply community blacklists.</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" className="sr-only peer" defaultChecked />
                <div className="w-11 h-6 bg-secondary peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
              </label>
            </div>
            <div className="flex items-center justify-between p-4 border border-border rounded-lg bg-background/50">
              <div className="space-y-0.5 w-full">
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <label className="text-sm font-medium">Outbound WAF (Content Inspection)</label>
                    <p className="text-xs text-muted-foreground">Inspect request bodies to block sensitive data leaks and injection attacks.</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input 
                      type="checkbox" 
                      name="enable_waf"
                      checked={formData.enable_waf === 'true'}
                      onChange={(e) => setFormData({ ...formData, enable_waf: e.target.checked ? 'true' : 'false' })}
                      className="sr-only peer" 
                    />
                    <div className="w-11 h-6 bg-secondary peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
                  </label>
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
                      className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary font-mono text-xs"
                    />
                  </div>
                )}
              </div>
            </div>
            {/* Security toggles — compact grid */}
            <label className="text-xs font-medium text-muted-foreground mb-1 block">Security & Filtering</label>
            <div className="grid grid-cols-2 lg:grid-cols-3 gap-2">
              {[
                { name: 'block_direct_ip', label: 'Block Direct IP', desc: 'Prevent DNS bypass' },
                { name: 'enable_safesearch', label: 'SafeSearch', desc: 'Google/Bing/DDG' },
                { name: 'enable_youtube_restricted', label: 'YouTube Restricted', desc: 'Hide mature content' },
                { name: 'enable_content_filtering', label: 'Content Filtering', desc: 'Block dangerous files' },
              ].map(t => (
                <div key={t.name} className="flex items-center justify-between p-3 border border-border rounded-lg bg-background/30">
                  <div>
                    <p className="text-xs font-medium">{t.label}</p>
                    <p className="text-[10px] text-muted-foreground">{t.desc}</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer shrink-0 ml-2">
                    <input type="checkbox" name={t.name} checked={formData[t.name] === 'true'}
                      onChange={(e) => setFormData({ ...formData, [t.name]: e.target.checked ? 'true' : 'false' })}
                      className="sr-only peer" />
                    <div className="w-9 h-5 bg-secondary rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-primary"></div>
                  </label>
                </div>
              ))}
            </div>
            {formData.enable_content_filtering === 'true' && (
              <div className="mt-3 p-3 border border-border/50 rounded-lg bg-background/20">
                <label className="text-[10px] text-muted-foreground">Blocked Extensions</label>
                <input type="text" name="blocked_file_types" value={formData.blocked_file_types || 'exe,bat,cmd,dll,js'} onChange={handleChange}
                  placeholder="exe,bat,mp4,zip" className="w-full mt-1 bg-background border border-border rounded-md px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary" />
              </div>
            )}
          </CardContent>
        </Card>

        {/* Account & Maintenance — side by side */}
        <div className="grid gap-4 lg:grid-cols-2">
          <ChangePassword />
          <Maintenance />
        </div>
      </div>
    </div>
  );
}