import { Card, CardContent } from '../components/ui/card';
import { useApi } from '../hooks/useApi';
import { api } from '../lib/api';
import { Ban, Globe, Server, Plus, Trash2, Download, Map } from 'lucide-react';
import { useState } from 'react';
import toast from 'react-hot-toast';

export function Blacklists() {
  const [activeTab, setActiveTab] = useState<'ip' | 'domain'>('ip');
  const [isAdding, setIsAdding] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const [isGeoBlocking, setIsGeoBlocking] = useState(false);
  
  const [newItem, setNewItem] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [importUrl, setImportUrl] = useState('');
  const [geoCountry, setGeoCountry] = useState('');
  
  const { data: ipData, execute: refreshIps } = useApi<any>('ip-blacklist');
  const { data: domainData, execute: refreshDomains } = useApi<any>('domain-blacklist');

  const ips = ipData?.blacklist || [];
  const domains = domainData?.blacklist || [];

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newItem) return;

    const endpoint = activeTab === 'ip' ? 'ip-blacklist' : 'domain-blacklist';
    const payload = activeTab === 'ip' 
      ? { ip_address: newItem, description: newDesc }
      : { domain: newItem, description: newDesc };

    const loadingToast = toast.loading(`Adding ${activeTab}...`);
    try {
      await api.post(endpoint, payload);
      toast.success('Rule added successfully', { id: loadingToast });
      setNewItem('');
      setNewDesc('');
      setIsAdding(false);
      activeTab === 'ip' ? refreshIps() : refreshDomains();
    } catch (err: any) {
      toast.error(err.response?.data?.message || 'Failed to add rule', { id: loadingToast });
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm('Are you sure you want to delete this rule?')) return;
    
    const endpoint = activeTab === 'ip' ? `ip-blacklist/${id}` : `domain-blacklist/${id}`;
    const loadingToast = toast.loading(`Deleting ${activeTab}...`);
    
    try {
      await api.delete(endpoint);
      toast.success('Rule deleted successfully', { id: loadingToast });
      activeTab === 'ip' ? refreshIps() : refreshDomains();
    } catch (err: any) {
      toast.error(err.response?.data?.message || 'Failed to delete rule', { id: loadingToast });
    }
  };

  const handleImport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!importUrl) return;

    const loadingToast = toast.loading(`Importing ${activeTab}s from URL...`);
    try {
      const response = await api.post('blacklists/import', {
        type: activeTab,
        url: importUrl
      });
      toast.success(`Imported ${response.data.imported_count || 0} rules successfully`, { id: loadingToast });
      setImportUrl('');
      setIsImporting(false);
      activeTab === 'ip' ? refreshIps() : refreshDomains();
    } catch (err: any) {
      toast.error(err.response?.data?.message || 'Failed to import rules', { id: loadingToast });
    }
  };

  const handleGeoBlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!geoCountry) return;

    const loadingToast = toast.loading(`Importing IP blocks for ${geoCountry}...`);
    try {
      const response = await api.post('blacklists/import-geo', {
        countries: [geoCountry]
      });
      toast.success(`Imported ${response.data.imported_count || 0} IPs successfully`, { id: loadingToast });
      setGeoCountry('');
      setIsGeoBlocking(false);
      refreshIps();
    } catch (err: any) {
      toast.error(err.response?.data?.message || 'Failed to import GeoIP blocks', { id: loadingToast });
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Blacklists</h1>
          <p className="text-muted-foreground">Manage IP and Domain blocking rules</p>
        </div>
        <div className="flex gap-2">
          {activeTab === 'ip' && (
            <button 
              onClick={() => { setIsGeoBlocking(!isGeoBlocking); setIsAdding(false); setIsImporting(false); }}
              className="flex items-center px-4 py-2 bg-secondary text-secondary-foreground rounded-md text-sm font-medium hover:bg-secondary/80 transition-colors"
            >
              <Map className="w-4 h-4 mr-2" />
              Geo-Block
            </button>
          )}
          <button 
            onClick={() => { setIsImporting(!isImporting); setIsAdding(false); setIsGeoBlocking(false); }}
            className="flex items-center px-4 py-2 bg-secondary text-secondary-foreground rounded-md text-sm font-medium hover:bg-secondary/80 transition-colors"
          >
            <Download className="w-4 h-4 mr-2" />
            Import URL
          </button>
          <button 
            onClick={() => { setIsAdding(!isAdding); setIsImporting(false); setIsGeoBlocking(false); }}
            className="flex items-center px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 transition-colors"
          >
            <Plus className={`w-4 h-4 mr-2 transition-transform ${isAdding ? 'rotate-45' : ''}`} />
            {isAdding ? 'Cancel' : 'Add Rule'}
          </button>
        </div>
      </div>

      {isAdding && (
        <Card className="bg-card/50 border-primary/50">
          <CardContent className="pt-6">
            <form onSubmit={handleAdd} className="flex gap-4 items-end">
              <div className="flex-1 space-y-2">
                <label className="text-sm font-medium">{activeTab === 'ip' ? 'IP Address' : 'Domain'}</label>
                <input 
                  type="text" 
                  value={newItem}
                  onChange={(e) => setNewItem(e.target.value)}
                  placeholder={activeTab === 'ip' ? 'e.g. 192.168.1.100' : 'e.g. bad-domain.com'}
                  className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                  required
                />
              </div>
              <div className="flex-1 space-y-2">
                <label className="text-sm font-medium">Description (Optional)</label>
                <input 
                  type="text" 
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  placeholder="Why is this blocked?"
                  className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
              <button type="submit" className="px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 transition-colors h-10">
                Save Rule
              </button>
            </form>
          </CardContent>
        </Card>
      )}

      {isImporting && (
        <Card className="bg-card/50 border-secondary">
          <CardContent className="pt-6">
            <form onSubmit={handleImport} className="flex gap-4 items-end">
              <div className="flex-1 space-y-2">
                <label className="text-sm font-medium">List URL (e.g. GitHub raw file)</label>
                <input 
                  type="url" 
                  value={importUrl}
                  onChange={(e) => setImportUrl(e.target.value)}
                  placeholder="https://raw.githubusercontent.com/..."
                  className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                  required
                />
              </div>
              <button type="submit" className="px-4 py-2 bg-secondary text-secondary-foreground rounded-md text-sm font-medium hover:bg-secondary/80 transition-colors h-10">
                Import List
              </button>
            </form>
            <p className="text-xs text-muted-foreground mt-3">The URL must point to a plain text file with one {activeTab} per line. Comments starting with # are ignored.</p>
          </CardContent>
        </Card>
      )}

      {isGeoBlocking && activeTab === 'ip' && (
        <Card className="bg-card/50 border-secondary">
          <CardContent className="pt-6">
            <form onSubmit={handleGeoBlock} className="flex gap-4 items-end">
              <div className="flex-1 space-y-2">
                <label className="text-sm font-medium">Country Code (2 letters)</label>
                <input 
                  type="text" 
                  value={geoCountry}
                  onChange={(e) => setGeoCountry(e.target.value.toUpperCase())}
                  placeholder="e.g. CN, RU, KP"
                  maxLength={2}
                  className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                  required
                />
              </div>
              <button type="submit" className="px-4 py-2 bg-secondary text-secondary-foreground rounded-md text-sm font-medium hover:bg-secondary/80 transition-colors h-10">
                Download & Block IPs
              </button>
            </form>
            <p className="text-xs text-muted-foreground mt-3">This will fetch all known IPv4 blocks for the specified country and add them to your IP Blacklist.</p>
          </CardContent>
        </Card>
      )}

      <div className="flex space-x-1 bg-card/50 p-1 rounded-lg w-fit border border-border">
        <button 
          onClick={() => setActiveTab('ip')}
          className={`flex items-center px-4 py-2 rounded-md text-sm font-medium transition-colors ${activeTab === 'ip' ? 'bg-[#1f1f1f] text-white shadow-sm' : 'text-muted-foreground hover:text-white'}`}
        >
          <Server className="w-4 h-4 mr-2" />
          IP Addresses
          <span className="ml-2 bg-secondary text-xs px-2 py-0.5 rounded-full">{ips.length}</span>
        </button>
        <button 
          onClick={() => setActiveTab('domain')}
          className={`flex items-center px-4 py-2 rounded-md text-sm font-medium transition-colors ${activeTab === 'domain' ? 'bg-[#1f1f1f] text-white shadow-sm' : 'text-muted-foreground hover:text-white'}`}
        >
          <Globe className="w-4 h-4 mr-2" />
          Domains
          <span className="ml-2 bg-secondary text-xs px-2 py-0.5 rounded-full">{domains.length}</span>
        </button>
      </div>

      <Card className="bg-card/50">
        <CardContent className="p-0">
          <table className="w-full text-sm text-left">
            <thead className="text-xs text-muted-foreground uppercase bg-secondary/50 border-b border-border">
              <tr>
                <th className="px-6 py-4 font-medium">Target</th>
                <th className="px-6 py-4 font-medium">Description</th>
                <th className="px-6 py-4 font-medium">Date Added</th>
                <th className="px-6 py-4 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {activeTab === 'ip' && ips.map((item: any, i: number) => (
                <tr key={i} className="hover:bg-secondary/20 transition-colors">
                  <td className="px-6 py-4 font-medium text-white">{item.ip_address}</td>
                  <td className="px-6 py-4 text-muted-foreground">{item.description || '-'}</td>
                  <td className="px-6 py-4 text-muted-foreground">{new Date(item.created_at).toLocaleDateString()}</td>
                  <td className="px-6 py-4 text-right">
                    <button 
                      onClick={() => handleDelete(item.id)}
                      className="text-destructive hover:text-red-400 transition-colors p-2 rounded-md hover:bg-destructive/10"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
              
              {activeTab === 'domain' && domains.map((item: any, i: number) => (
                <tr key={i} className="hover:bg-secondary/20 transition-colors">
                  <td className="px-6 py-4 font-medium text-white">{item.domain}</td>
                  <td className="px-6 py-4 text-muted-foreground">{item.description || '-'}</td>
                  <td className="px-6 py-4 text-muted-foreground">{new Date(item.created_at).toLocaleDateString()}</td>
                  <td className="px-6 py-4 text-right">
                    <button 
                      onClick={() => handleDelete(item.id)}
                      className="text-destructive hover:text-red-400 transition-colors p-2 rounded-md hover:bg-destructive/10"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}

              {((activeTab === 'ip' && ips.length === 0) || (activeTab === 'domain' && domains.length === 0)) && (
                <tr>
                  <td colSpan={4} className="px-6 py-8 text-center text-muted-foreground">
                    <Ban className="w-8 h-8 mx-auto mb-3 opacity-20" />
                    No {activeTab === 'ip' ? 'IP addresses' : 'domains'} in blacklist
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}