import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card';
import { useApi } from '../hooks/useApi';
import { Save, Download, Upload, Shield, Database, Network } from 'lucide-react';
import { useState, useEffect } from 'react';

export function Settings() {
  const { data: settingsData } = useApi<any>('settings');
  const [formData, setFormData] = useState<any>({});

  useEffect(() => {
    if (settingsData) {
      setFormData(settingsData);
    }
  }, [settingsData]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSave = async () => {
    try {
      const response = await fetch('/api/settings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData)
      });
      if (response.ok) {
        alert("Settings saved successfully!");
      } else {
        alert("Failed to save settings");
      }
    } catch (err) {
      alert("Error saving settings");
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500 max-w-4xl">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Settings</h1>
          <p className="text-muted-foreground">Configure proxy behavior and security</p>
        </div>
        <button 
          onClick={handleSave}
          className="flex items-center px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 transition-colors"
        >
          <Save className="w-4 h-4 mr-2" />
          Save Changes
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
              <button className="flex-1 flex flex-col items-center justify-center p-6 border border-border rounded-lg bg-background/50 hover:bg-secondary/50 transition-colors">
                <Download className="w-6 h-6 mb-2 text-primary" />
                <span className="text-sm font-medium">Backup Config</span>
                <span className="text-xs text-muted-foreground mt-1">Download settings JSON</span>
              </button>
              <button className="flex-1 flex flex-col items-center justify-center p-6 border border-border rounded-lg bg-background/50 hover:bg-secondary/50 transition-colors">
                <Upload className="w-6 h-6 mb-2 text-emerald-500" />
                <span className="text-sm font-medium">Restore Config</span>
                <span className="text-xs text-muted-foreground mt-1">Upload settings JSON</span>
              </button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}