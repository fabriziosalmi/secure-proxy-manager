import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card';
import { useApi } from '../hooks/useApi';
import { Save, Download, Upload, Shield, Database, Network, Trash2, Key } from 'lucide-react';
import { useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import { api } from '../lib/api';

export function Settings() {
  const { data: settingsData, execute: refreshSettings } = useApi<any>('settings');
  const [formData, setFormData] = useState<any>({});
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    if (settingsData) {
      setFormData(settingsData);
    }
  }, [settingsData]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSave = async () => {
    setIsSaving(true);
    const loadingToast = toast.loading('Saving settings...');
    try {
      await api.post('settings', formData);
      toast.success('Settings saved successfully!', { id: loadingToast });
      
      // Auto reload config after saving
      toast.promise(
        api.post('maintenance/reload-config'),
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

  const handleClearCache = async () => {
    toast.promise(
      api.post('maintenance/clear-cache'),
      {
        loading: 'Clearing proxy cache...',
        success: 'Cache cleared successfully!',
        error: 'Failed to clear cache.',
      }
    );
  };

  const handleBackup = async () => {
    try {
      const response = await api.get('maintenance/backup-config');
      if (response.data && response.data.data) {
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(response.data.data, null, 2));
        const downloadAnchorNode = document.createElement('a');
        downloadAnchorNode.setAttribute("href",     dataStr);
        downloadAnchorNode.setAttribute("download", "proxy_backup.json");
        document.body.appendChild(downloadAnchorNode);
        downloadAnchorNode.click();
        downloadAnchorNode.remove();
        toast.success("Backup downloaded!");
      }
    } catch (e) {
      toast.error("Failed to generate backup");
    }
  };

  const handleRestore = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = e => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;
      const reader = new FileReader();
      reader.readAsText(file, "UTF-8");
      reader.onload = async readerEvent => {
        try {
          const content = readerEvent.target?.result as string;
          const config = JSON.parse(content);
          
          const loadingToast = toast.loading('Restoring configuration...');
          await api.post('maintenance/restore-config', { config });
          toast.success('Configuration restored!', { id: loadingToast });
          refreshSettings();
        } catch (error) {
          toast.error('Invalid backup file');
        }
      }
    }
    input.click();
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
            <div className="flex items-center justify-between p-4 border border-border rounded-lg bg-background/50">
              <div className="space-y-0.5">
                <label className="text-sm font-medium">HTTPS Inspection (SSL Bump)</label>
                <p className="text-xs text-muted-foreground">Decrypt and inspect HTTPS traffic. Required for WAF to work on secure sites.</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  name="enable_https_filtering"
                  checked={formData.enable_https_filtering === 'true' || formData.enable_https_filtering === true}
                  onChange={(e) => setFormData({ ...formData, enable_https_filtering: e.target.checked ? 'true' : 'false' })}
                  className="sr-only peer" 
                />
                <div className="w-11 h-6 bg-secondary peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
              </label>
            </div>

            <div className="flex items-center justify-between p-4 border border-border rounded-lg bg-background/50">
              <div className="space-y-0.5">
                <label className="text-sm font-medium">Aggressive Caching</label>
                <p className="text-xs text-muted-foreground">Ignore cache-control headers for static files (images, css, js) to force caching. Great for bandwidth saving.</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  name="aggressive_caching"
                  checked={formData.aggressive_caching === 'true' || formData.aggressive_caching === true}
                  onChange={(e) => setFormData({ ...formData, aggressive_caching: e.target.checked ? 'true' : 'false' })}
                  className="sr-only peer" 
                />
                <div className="w-11 h-6 bg-secondary peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
              </label>
            </div>

            <div className="flex items-center justify-between p-4 border border-border rounded-lg bg-background/50">
              <div className="space-y-0.5">
                <label className="text-sm font-medium">Offline Mode (Stale Cache)</label>
                <p className="text-xs text-muted-foreground">Serve expired cached pages if the destination server is offline.</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  name="enable_offline_mode"
                  checked={formData.enable_offline_mode === 'true' || formData.enable_offline_mode === true}
                  onChange={(e) => setFormData({ ...formData, enable_offline_mode: e.target.checked ? 'true' : 'false' })}
                  className="sr-only peer" 
                />
                <div className="w-11 h-6 bg-secondary peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
              </label>
            </div>

            <div className="p-4 border border-border rounded-lg bg-background/50">
              <label className="text-sm font-medium">Cache Bypass Domains</label>
              <p className="text-xs text-muted-foreground mb-2">Domains that should NEVER be cached (comma-separated).</p>
              <input 
                type="text" 
                name="cache_bypass_domains"
                value={formData.cache_bypass_domains || ''}
                onChange={handleChange}
                placeholder="e.g. banking.com, api.internal.local"
                className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/50">
          <CardHeader>
            <div className="flex items-center space-x-2">
              <Shield className="w-5 h-5 text-indigo-500" />
              <CardTitle>Access Control</CardTitle>
            </div>
            <CardDescription>Manage who and when can use the proxy</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between p-4 border border-border rounded-lg bg-background/50">
              <div className="space-y-0.5 w-full">
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <label className="text-sm font-medium">Time-based Restrictions</label>
                    <p className="text-xs text-muted-foreground">Only allow internet access during specific hours.</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input 
                      type="checkbox" 
                      name="enable_time_restrictions"
                      checked={formData.enable_time_restrictions === 'true' || formData.enable_time_restrictions === true}
                      onChange={(e) => setFormData({ ...formData, enable_time_restrictions: e.target.checked ? 'true' : 'false' })}
                      className="sr-only peer" 
                    />
                    <div className="w-11 h-6 bg-secondary peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
                  </label>
                </div>
                {formData.enable_time_restrictions === 'true' && (
                  <div className="flex gap-4 mt-2 pt-2 border-t border-border/50">
                    <div className="flex-1 space-y-1">
                      <label className="text-xs text-muted-foreground">Start Time</label>
                      <input 
                        type="time" 
                        name="time_restriction_start"
                        value={formData.time_restriction_start || '09:00'}
                        onChange={handleChange}
                        className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                      />
                    </div>
                    <div className="flex-1 space-y-1">
                      <label className="text-xs text-muted-foreground">End Time</label>
                      <input 
                        type="time" 
                        name="time_restriction_end"
                        value={formData.time_restriction_end || '17:00'}
                        onChange={handleChange}
                        className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                      />
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="flex items-center justify-between p-4 border border-border rounded-lg bg-background/50">
              <div className="space-y-0.5 w-full">
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <label className="text-sm font-medium">Proxy Authentication</label>
                    <p className="text-xs text-muted-foreground">Require username/password to use the proxy.</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input 
                      type="checkbox" 
                      name="enable_proxy_auth"
                      checked={formData.enable_proxy_auth === 'true' || formData.enable_proxy_auth === true}
                      onChange={(e) => setFormData({ ...formData, enable_proxy_auth: e.target.checked ? 'true' : 'false' })}
                      className="sr-only peer" 
                    />
                    <div className="w-11 h-6 bg-secondary peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
                  </label>
                </div>
                {formData.enable_proxy_auth === 'true' && (
                  <div className="mt-2 pt-2 border-t border-border/50">
                    <label className="text-xs text-muted-foreground">Authentication Method</label>
                    <select 
                      name="auth_method"
                      value={formData.auth_method || 'basic'}
                      onChange={handleChange}
                      className="w-full mt-1 bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                    >
                      <option value="basic">Basic (Standard)</option>
                      <option value="digest">Digest (More Secure)</option>
                    </select>
                  </div>
                )}
              </div>
            </div>
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
              <div className="space-y-0.5">
                <label className="text-sm font-medium">Outbound WAF (Content Inspection)</label>
                <p className="text-xs text-muted-foreground">Inspect request bodies to block sensitive data leaks and injection attacks.</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  name="enable_waf"
                  checked={formData.enable_waf === 'true' || formData.enable_waf === true}
                  onChange={(e) => setFormData({ ...formData, enable_waf: e.target.checked ? 'true' : 'false' })}
                  className="sr-only peer" 
                />
                <div className="w-11 h-6 bg-secondary peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
              </label>
            </div>
            <div className="flex items-center justify-between p-4 border border-border rounded-lg bg-background/50">
              <div className="space-y-0.5">
                <label className="text-sm font-medium">SSL Bump (HTTPS Interception)</label>
                <p className="text-xs text-muted-foreground">Decrypt and inspect HTTPS traffic. Requires installing CA cert on clients.</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" className="sr-only peer" />
                <div className="w-11 h-6 bg-secondary peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
              </label>
            </div>
            <div className="flex items-center justify-between p-4 border border-border rounded-lg bg-background/50">
              <div className="space-y-0.5">
                <label className="text-sm font-medium">Block Direct IP Access</label>
                <p className="text-xs text-muted-foreground">Prevent bypassing DNS blacklists by directly entering IP addresses in the browser.</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  name="block_direct_ip"
                  checked={formData.block_direct_ip === 'true' || formData.block_direct_ip === true}
                  onChange={(e) => setFormData({ ...formData, block_direct_ip: e.target.checked ? 'true' : 'false' })}
                  className="sr-only peer" 
                />
                <div className="w-11 h-6 bg-secondary peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
              </label>
            </div>

            <div className="flex items-center justify-between p-4 border border-border rounded-lg bg-background/50">
              <div className="space-y-0.5">
                <label className="text-sm font-medium">SafeSearch Enforcement</label>
                <p className="text-xs text-muted-foreground">Force SafeSearch for all users on Google, Bing, and DuckDuckGo (Requires HTTPS Inspection).</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  name="enable_safesearch"
                  checked={formData.enable_safesearch === 'true' || formData.enable_safesearch === true}
                  onChange={(e) => setFormData({ ...formData, enable_safesearch: e.target.checked ? 'true' : 'false' })}
                  className="sr-only peer" 
                />
                <div className="w-11 h-6 bg-secondary peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
              </label>
            </div>

            <div className="flex items-center justify-between p-4 border border-border rounded-lg bg-background/50">
              <div className="space-y-0.5">
                <label className="text-sm font-medium">YouTube Restricted Mode</label>
                <p className="text-xs text-muted-foreground">Force Strict Restricted Mode on YouTube to hide mature content (Requires HTTPS Inspection).</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  name="enable_youtube_restricted"
                  checked={formData.enable_youtube_restricted === 'true' || formData.enable_youtube_restricted === true}
                  onChange={(e) => setFormData({ ...formData, enable_youtube_restricted: e.target.checked ? 'true' : 'false' })}
                  className="sr-only peer" 
                />
                <div className="w-11 h-6 bg-secondary peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
              </label>
            </div>
            
            <div className="flex items-center justify-between p-4 border border-border rounded-lg bg-background/50">
              <div className="space-y-0.5 w-full">
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <label className="text-sm font-medium">Content Filtering (Block File Extensions)</label>
                    <p className="text-xs text-muted-foreground">Block downloads of potentially dangerous file types.</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input 
                      type="checkbox" 
                      name="enable_content_filtering"
                      checked={formData.enable_content_filtering === 'true' || formData.enable_content_filtering === true}
                      onChange={(e) => setFormData({ ...formData, enable_content_filtering: e.target.checked ? 'true' : 'false' })}
                      className="sr-only peer" 
                    />
                    <div className="w-11 h-6 bg-secondary peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
                  </label>
                </div>
                {formData.enable_content_filtering === 'true' && (
                  <div className="mt-2 pt-2 border-t border-border/50">
                    <input 
                      type="text" 
                      name="blocked_file_types"
                      value={formData.blocked_file_types || 'exe,bat,cmd,dll,js'}
                      onChange={handleChange}
                      placeholder="e.g. exe,bat,mp4,zip"
                      className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                    />
                    <p className="text-xs text-muted-foreground mt-1">Comma-separated list of extensions without the dot.</p>
                  </div>
                )}
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/50">
          <CardHeader>
            <div className="flex items-center space-x-2">
              <Database className="w-5 h-5 text-muted-foreground" />
              <CardTitle>Maintenance</CardTitle>
            </div>
            <CardDescription>System backup and state management</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex gap-4">
              <button 
                onClick={handleBackup}
                className="flex-1 flex flex-col items-center justify-center p-6 border border-border rounded-lg bg-background/50 hover:bg-secondary/50 transition-colors"
              >
                <Download className="w-6 h-6 mb-2 text-primary" />
                <span className="text-sm font-medium">Backup Config</span>
                <span className="text-xs text-muted-foreground mt-1">Download settings JSON</span>
              </button>
              <button 
                onClick={handleRestore}
                className="flex-1 flex flex-col items-center justify-center p-6 border border-border rounded-lg bg-background/50 hover:bg-secondary/50 transition-colors"
              >
                <Upload className="w-6 h-6 mb-2 text-emerald-500" />
                <span className="text-sm font-medium">Restore Config</span>
                <span className="text-xs text-muted-foreground mt-1">Upload settings JSON</span>
              </button>
              <button 
                onClick={handleClearCache}
                className="flex-1 flex flex-col items-center justify-center p-6 border border-border rounded-lg bg-background/50 hover:bg-destructive/10 transition-colors group"
              >
                <Trash2 className="w-6 h-6 mb-2 text-destructive group-hover:text-red-400" />
                <span className="text-sm font-medium text-destructive group-hover:text-red-400">Clear Cache</span>
                <span className="text-xs text-muted-foreground mt-1">Free up proxy memory/disk</span>
              </button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}