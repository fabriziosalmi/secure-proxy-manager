import { Card, CardContent } from '../components/ui/card';
import { useApi } from '../hooks/useApi';
import { api, getErrorMessage } from '../lib/api';
import type { IpEntry, DomainEntry, WhitelistEntry, ListResponse } from '../types';
import { Ban, Globe, Server, Plus, Trash2, Download, Map, Database, Shield, CheckCircle, Loader2 } from 'lucide-react';
import { useState } from 'react';
import toast from 'react-hot-toast';

export function Blacklists() {
  const [activeTab, setActiveTab] = useState<'ip' | 'domain' | 'whitelist'>('ip');
  const [isAdding, setIsAdding] = useState(false);
  const [isBulkAdding, setIsBulkAdding] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const [isGeoBlocking, setIsGeoBlocking] = useState(false);
  const [isPopularLists, setIsPopularLists] = useState(false);
  const [pendingDeleteId, setPendingDeleteId] = useState<number | null>(null);
  const [importingList, setImportingList] = useState<string | null>(null);

  const [newItem, setNewItem] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [bulkText, setBulkText] = useState('');
  const [importUrl, setImportUrl] = useState('');
  const [geoCountry, setGeoCountry] = useState('');
  
  const { data: ipData, execute: refreshIps } = useApi<ListResponse<IpEntry>>('ip-blacklist');
  const { data: domainData, execute: refreshDomains } = useApi<ListResponse<DomainEntry>>('domain-blacklist');
  const { data: whitelistData, execute: refreshWhitelists } = useApi<ListResponse<WhitelistEntry>>('ip-whitelist');

  const ips = ipData?.data ?? [];
  const domains = domainData?.data ?? [];
  const whitelists = whitelistData?.data ?? [];

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newItem) return;

    let endpoint = '';
    let payload = {};
    
    if (activeTab === 'ip') {
      endpoint = 'ip-blacklist';
      payload = { ip: newItem, description: newDesc };
    } else if (activeTab === 'domain') {
      endpoint = 'domain-blacklist';
      payload = { domain: newItem, description: newDesc };
    } else {
      endpoint = 'ip-whitelist';
      payload = { ip: newItem, description: newDesc };
    }

    const loadingToast = toast.loading(`Adding ${activeTab}...`);
    try {
      await api.post(endpoint, payload);
      toast.success('Rule added successfully', { id: loadingToast });
      setNewItem('');
      setNewDesc('');
      setIsAdding(false);
      
      if (activeTab === 'ip') refreshIps();
      else if (activeTab === 'domain') refreshDomains();
      else refreshWhitelists();
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to add rule'), { id: loadingToast });
    }
  };

  const handleBulkAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!bulkText.trim()) return;

    const loadingToast = toast.loading(`Importing ${activeTab} entries...`);
    try {
      const response = await api.post('blacklists/import', {
        type: activeTab === 'whitelist' ? 'ip' : activeTab,
        content: bulkText
      });
      const added = response.data.data?.added || 0;
      const skipped = response.data.data?.skipped || 0;
      toast.success(`Added ${added} entries${skipped > 0 ? `, ${skipped} skipped` : ''}`, { id: loadingToast });
      setBulkText('');
      setIsBulkAdding(false);
      if (activeTab === 'ip') refreshIps();
      else if (activeTab === 'domain') refreshDomains();
      else refreshWhitelists();
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to import entries'), { id: loadingToast });
    }
  };

  const handleDelete = async (id: number) => {
    let endpoint = '';
    if (activeTab === 'ip') endpoint = `ip-blacklist/${id}`;
    else if (activeTab === 'domain') endpoint = `domain-blacklist/${id}`;
    else endpoint = `ip-whitelist/${id}`;

    const loadingToast = toast.loading(`Deleting ${activeTab}...`);
    try {
      await api.delete(`/api/${endpoint}`);
      toast.success('Rule deleted successfully', { id: loadingToast });
      setPendingDeleteId(null);
      if (activeTab === 'ip') refreshIps();
      else if (activeTab === 'domain') refreshDomains();
      else refreshWhitelists();
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to delete rule'), { id: loadingToast });
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
      toast.success(`Imported ${response.data.data?.added || 0} rules successfully`, { id: loadingToast });
      setImportUrl('');
      setIsImporting(false);
      activeTab === 'ip' ? refreshIps() : refreshDomains();
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to import rules'), { id: loadingToast });
    }
  };

  const handleGeoBlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!geoCountry) return;

    // Accept space or comma separated country codes: "CN, RU KP" → ["CN","RU","KP"]
    const countries = geoCountry
      .split(/[\s,]+/)
      .map(c => c.trim().toUpperCase())
      .filter(c => c.length === 2);

    if (countries.length === 0) return;

    const loadingToast = toast.loading(`Importing IP blocks for ${countries.join(', ')}...`);
    try {
      const response = await api.post('blacklists/import-geo', {
        countries
      });
      toast.success(`Imported ${response.data.data?.imported || 0} IPs successfully`, { id: loadingToast });
      setGeoCountry('');
      setIsGeoBlocking(false);
      refreshIps();
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to import GeoIP blocks'), { id: loadingToast });
    }
  };

  const handlePopularListImport = async (listUrl: string, listName: string) => {
    setImportingList(listName);
    const loadingToast = toast.loading(`Downloading ${listName}… this may take 1-2 minutes for large lists.`);
    try {
      const response = await api.post('blacklists/import', {
        url: listUrl,
        type: activeTab === 'whitelist' ? 'ip' : activeTab
      });
      const added = response.data.data?.added || 0;
      const skipped = response.data.data?.skipped || 0;
      toast.success(
        `${listName}: added ${added.toLocaleString()} entries${skipped > 0 ? `, ${skipped.toLocaleString()} skipped` : ''}`,
        { id: loadingToast, duration: 6000 }
      );
      activeTab === 'ip' ? refreshIps() : refreshDomains();
    } catch (err) {
      toast.error(getErrorMessage(err, `Failed to import ${listName}`), { id: loadingToast, duration: 8000 });
    } finally {
      setImportingList(null);
    }
  };

  const popularIpLists = [
    { name: 'Firehol Level 1 (High Threat)', url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', desc: 'A general purpose blocklist protecting against active threats' },
    { name: 'Spamhaus DROP', url: 'https://www.spamhaus.org/drop/drop.txt', desc: 'Don\'t Route Or Peer Lists (Direct malware/botnets)' },
    { name: 'Emerging Threats', url: 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt', desc: 'Known compromised hosts and botnet C&C' },
    { name: 'CINS Army List', url: 'https://cinsarmy.com/list/ci-badguys.txt', desc: 'High-confidence malicious IP addresses' }
  ];

  const popularDomainLists = [
    { name: 'StevenBlack Ad/Malware', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', desc: 'Consolidated host files from multiple sources' },
    { name: 'Abuse.ch URLhaus Domains', url: 'https://urlhaus.abuse.ch/downloads/hostfile/', desc: 'Active malware distribution domains from URLhaus' },
    { name: 'Phishing Army', url: 'https://phishing.army/download/phishing_army_blocklist_extended.txt', desc: 'Domains actively involved in phishing' }
  ];

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
              onClick={() => { setIsGeoBlocking(!isGeoBlocking); setIsAdding(false); setIsImporting(false); setIsPopularLists(false); setIsBulkAdding(false); }}
              className={`flex items-center px-4 py-2 rounded-md text-sm font-medium transition-colors ${isGeoBlocking ? 'bg-primary/20 text-primary' : 'bg-secondary text-secondary-foreground hover:bg-secondary/80'}`}
            >
              <Map className="w-4 h-4 mr-2" />
              Geo-Block
            </button>
          )}
          
          {activeTab !== 'whitelist' && (
            <button
              type="button"
              onClick={() => { setIsPopularLists(!isPopularLists); setIsAdding(false); setIsGeoBlocking(false); setIsImporting(false); setIsBulkAdding(false); }}
              className={`flex items-center px-4 py-2 rounded-md text-sm font-medium transition-colors ${isPopularLists ? 'bg-primary/20 text-primary' : 'bg-secondary text-secondary-foreground hover:bg-secondary/80'}`}
            >
              <Database className="w-4 h-4 mr-2" />
              Popular Lists
            </button>
          )}

          {activeTab !== 'whitelist' && (
            <button
              type="button"
              onClick={() => { setIsImporting(!isImporting); setIsAdding(false); setIsGeoBlocking(false); setIsPopularLists(false); setIsBulkAdding(false); }}
              className={`flex items-center px-4 py-2 rounded-md text-sm font-medium transition-colors ${isImporting ? 'bg-primary/20 text-primary' : 'bg-secondary text-secondary-foreground hover:bg-secondary/80'}`}
            >
              <Download className="w-4 h-4 mr-2" />
              Import URL
            </button>
          )}
          <button
            type="button"
            onClick={() => { setIsBulkAdding(!isBulkAdding); setIsAdding(false); setIsImporting(false); setIsGeoBlocking(false); setIsPopularLists(false); }}
            className={`flex items-center px-4 py-2 rounded-md text-sm font-medium transition-colors ${isBulkAdding ? 'bg-primary/20 text-primary' : 'bg-secondary text-secondary-foreground hover:bg-secondary/80'}`}
          >
            <Plus className="w-4 h-4 mr-2" />
            Bulk Add
          </button>
          <button
            onClick={() => { setIsAdding(!isAdding); setIsImporting(false); setIsGeoBlocking(false); setIsPopularLists(false); setIsBulkAdding(false); }}
            className={`flex items-center px-4 py-2 rounded-md text-sm font-medium transition-colors ${isAdding ? 'bg-destructive/90 text-destructive-foreground' : 'bg-primary text-primary-foreground hover:bg-primary/90'}`}
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
                <label className="text-sm font-medium">
                  {activeTab === 'ip' ? 'IP Address' : activeTab === 'domain' ? 'Domain' : 'IP / CIDR Network'}
                </label>
                <input 
                  type="text" 
                  value={newItem}
                  onChange={(e) => setNewItem(e.target.value)}
                  placeholder={activeTab === 'ip' ? 'e.g. 192.168.1.100' : activeTab === 'domain' ? 'e.g. bad-domain.com' : 'e.g. 192.168.0.0/16'}
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

      {isBulkAdding && (
        <Card className="bg-card/50 border-primary/50">
          <CardContent className="pt-6">
            <form onSubmit={handleBulkAdd} className="space-y-3">
              <div className="space-y-2">
                <label className="text-sm font-medium">
                  {activeTab === 'domain' ? 'Domains' : 'IP Addresses / CIDR Networks'} — one per line
                </label>
                <textarea
                  value={bulkText}
                  onChange={(e) => setBulkText(e.target.value)}
                  placeholder={activeTab === 'domain'
                    ? 'bad-domain.com\nanother-domain.net\nads.example.org'
                    : '192.168.1.100\n10.0.0.0/8\n203.0.113.50'}
                  rows={6}
                  className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-primary resize-y"
                  required
                />
              </div>
              <p className="text-xs text-muted-foreground">Lines starting with # are ignored. Invalid entries are skipped.</p>
              <div className="flex gap-2">
                <button type="submit" className="px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 transition-colors">
                  Add All
                </button>
                <button type="button" onClick={() => setIsBulkAdding(false)} className="px-4 py-2 bg-secondary text-secondary-foreground rounded-md text-sm font-medium hover:bg-secondary/80 transition-colors">
                  Cancel
                </button>
              </div>
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

      {isPopularLists && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          {(activeTab === 'ip' ? popularIpLists : popularDomainLists).map((list, idx) => (
            <Card key={idx} className="bg-card/50 border-primary/20 hover:border-primary/50 transition-colors">
              <CardContent className="p-4 flex flex-col h-full justify-between">
                <div>
                  <div className="flex items-center space-x-2 mb-2">
                    <Shield className="w-4 h-4 text-primary" />
                    <h4 className="font-semibold">{list.name}</h4>
                  </div>
                  <p className="text-xs text-muted-foreground mb-4">{list.desc}</p>
                </div>
                <button
                  onClick={() => handlePopularListImport(list.url, list.name)}
                  disabled={importingList !== null}
                  className="w-full flex items-center justify-center px-4 py-2 bg-secondary text-secondary-foreground rounded-md text-sm font-medium hover:bg-secondary/80 transition-colors mt-auto disabled:opacity-60 disabled:cursor-not-allowed"
                >
                  {importingList === list.name ? (
                    <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Importing…</>
                  ) : (
                    <><Download className="w-4 h-4 mr-2" />Import List</>
                  )}
                </button>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {isGeoBlocking && activeTab === 'ip' && (
        <Card className="bg-card/50 border-secondary">
          <CardContent className="pt-6">
            <form onSubmit={handleGeoBlock} className="flex gap-4 items-end">
              <div className="flex-1 space-y-2">
                <label className="text-sm font-medium">Country Codes (comma or space separated)</label>
                <input
                  type="text"
                  value={geoCountry}
                  onChange={(e) => setGeoCountry(e.target.value.toUpperCase())}
                  placeholder="e.g. CN, RU, KP"
                  className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                  required
                />
              </div>
              <button type="submit" className="px-4 py-2 bg-secondary text-secondary-foreground rounded-md text-sm font-medium hover:bg-secondary/80 transition-colors h-10">
                Download & Block IPs
              </button>
            </form>
            <p className="text-xs text-muted-foreground mt-3">Fetches all known IPv4 blocks for each country and adds them to your IP Blacklist. Use 2-letter ISO codes: CN, RU, KP, IR…</p>
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
        <button
          type="button"
          onClick={() => { setActiveTab('whitelist'); setIsPopularLists(false); setIsImporting(false); setIsGeoBlocking(false); setIsBulkAdding(false); }}
          className={`flex items-center px-4 py-2 rounded-md text-sm font-medium transition-colors ${activeTab === 'whitelist' ? 'bg-green-500/20 text-green-500 shadow-sm' : 'text-muted-foreground hover:text-green-500'}`}
        >
          <CheckCircle className="w-4 h-4 mr-2" />
          IP Whitelist
          <span className="ml-2 bg-secondary text-xs px-2 py-0.5 rounded-full">{whitelists.length}</span>
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
              {activeTab === 'ip' && ips.map((item) => (
                <tr key={item.id} className="hover:bg-secondary/20 transition-colors">
                  <td className="px-6 py-4 font-medium text-white">{item.ip}</td>
                  <td className="px-6 py-4 text-muted-foreground">{item.description || '-'}</td>
                  <td className="px-6 py-4 text-muted-foreground">{item.added_date ? new Date(item.added_date).toLocaleDateString() : '-'}</td>
                  <td className="px-6 py-4 text-right">
                    {pendingDeleteId === item.id ? (
                      <div className="flex items-center justify-end gap-1">
                        <button type="button" onClick={() => handleDelete(item.id)} className="px-2 py-1 text-xs bg-destructive text-destructive-foreground rounded hover:bg-destructive/90 transition-colors">Confirm</button>
                        <button type="button" onClick={() => setPendingDeleteId(null)} className="px-2 py-1 text-xs bg-secondary text-foreground rounded hover:bg-secondary/80 transition-colors">Cancel</button>
                      </div>
                    ) : (
                      <button type="button" aria-label="Delete rule" onClick={() => setPendingDeleteId(item.id)} className="text-destructive hover:text-red-400 transition-colors p-2 rounded-md hover:bg-destructive/10">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              
              {activeTab === 'domain' && domains.map((item) => (
                <tr key={item.id} className="hover:bg-secondary/20 transition-colors">
                  <td className="px-6 py-4 font-medium text-white">{item.domain}</td>
                  <td className="px-6 py-4 text-muted-foreground">{item.description || '-'}</td>
                  <td className="px-6 py-4 text-muted-foreground">{item.added_date ? new Date(item.added_date).toLocaleDateString() : '-'}</td>
                  <td className="px-6 py-4 text-right">
                    {pendingDeleteId === item.id ? (
                      <div className="flex items-center justify-end gap-1">
                        <button type="button" onClick={() => handleDelete(item.id)} className="px-2 py-1 text-xs bg-destructive text-destructive-foreground rounded hover:bg-destructive/90 transition-colors">Confirm</button>
                        <button type="button" onClick={() => setPendingDeleteId(null)} className="px-2 py-1 text-xs bg-secondary text-foreground rounded hover:bg-secondary/80 transition-colors">Cancel</button>
                      </div>
                    ) : (
                      <button type="button" aria-label="Delete rule" onClick={() => setPendingDeleteId(item.id)} className="text-destructive hover:text-red-400 transition-colors p-2 rounded-md hover:bg-destructive/10">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}

              {activeTab === 'whitelist' && whitelists.map((item) => (
                <tr key={item.id} className="hover:bg-secondary/20 transition-colors">
                  <td className="px-6 py-4 font-medium text-green-500">{item.ip}</td>
                  <td className="px-6 py-4 text-muted-foreground">{item.description || '-'}</td>
                  <td className="px-6 py-4 text-muted-foreground">{item.added_date ? new Date(item.added_date).toLocaleDateString() : '-'}</td>
                  <td className="px-6 py-4 text-right">
                    {pendingDeleteId === item.id ? (
                      <div className="flex items-center justify-end gap-1">
                        <button type="button" onClick={() => handleDelete(item.id)} className="px-2 py-1 text-xs bg-destructive text-destructive-foreground rounded hover:bg-destructive/90 transition-colors">Confirm</button>
                        <button type="button" onClick={() => setPendingDeleteId(null)} className="px-2 py-1 text-xs bg-secondary text-foreground rounded hover:bg-secondary/80 transition-colors">Cancel</button>
                      </div>
                    ) : (
                      <button type="button" aria-label="Delete rule" onClick={() => setPendingDeleteId(item.id)} className="text-destructive hover:text-red-400 transition-colors p-2 rounded-md hover:bg-destructive/10">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}

              {((activeTab === 'ip' && ips.length === 0) || (activeTab === 'domain' && domains.length === 0) || (activeTab === 'whitelist' && whitelists.length === 0)) && (
                <tr>
                  <td colSpan={4} className="px-6 py-8 text-center text-muted-foreground">
                    <Ban className="w-8 h-8 mx-auto mb-3 opacity-20" />
                    No {activeTab === 'ip' ? 'IP addresses' : activeTab === 'domain' ? 'domains' : 'whitelisted networks'} found
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