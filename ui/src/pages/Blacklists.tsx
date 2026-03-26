import { Card, CardContent } from '../components/ui/card';
import { api, getErrorMessage } from '../lib/api';
import type { IpEntry, DomainEntry, WhitelistEntry } from '../types';
import { Ban, Globe, Server, Plus, Trash2, Download, Map, Database, Shield, CheckCircle, Loader2 } from 'lucide-react';
import { useState } from 'react';
import toast from 'react-hot-toast';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';

export function Blacklists() {
  const queryClient = useQueryClient();
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
  const [searchTerm, setSearchTerm] = useState('');
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 50;

  // Reset page when tab or search changes
  const resetPage = () => setPage(0);

  type PaginatedResponse<T> = { data: T[]; total: number };

  const { data: ipResult } = useQuery<PaginatedResponse<IpEntry>>({
    queryKey: ['blacklist', 'ip', page, searchTerm],
    queryFn: () => api.get(`ip-blacklist?limit=${PAGE_SIZE}&offset=${page * PAGE_SIZE}&search=${encodeURIComponent(searchTerm)}`).then(r => ({ data: r.data.data, total: r.data.total })),
  });
  const { data: domainResult } = useQuery<PaginatedResponse<DomainEntry>>({
    queryKey: ['blacklist', 'domain', page, searchTerm],
    queryFn: () => api.get(`domain-blacklist?limit=${PAGE_SIZE}&offset=${page * PAGE_SIZE}&search=${encodeURIComponent(searchTerm)}`).then(r => ({ data: r.data.data, total: r.data.total })),
  });
  const { data: whitelistResult } = useQuery<PaginatedResponse<WhitelistEntry>>({
    queryKey: ['whitelist', 'ip', page, searchTerm],
    queryFn: () => api.get(`ip-whitelist?limit=${PAGE_SIZE}&offset=${page * PAGE_SIZE}&search=${encodeURIComponent(searchTerm)}`).then(r => ({ data: r.data.data, total: r.data.total })),
  });

  const ips = ipResult?.data ?? [];
  const domains = domainResult?.data ?? [];
  const whitelists = whitelistResult?.data ?? [];
  const activeTotal = activeTab === 'ip' ? (ipResult?.total ?? 0) : activeTab === 'domain' ? (domainResult?.total ?? 0) : (whitelistResult?.total ?? 0);
  const totalPages = Math.ceil(activeTotal / PAGE_SIZE);

  const invalidateActive = () => {
    if (activeTab === 'ip') queryClient.invalidateQueries({ queryKey: ['blacklist', 'ip'] });
    else if (activeTab === 'domain') queryClient.invalidateQueries({ queryKey: ['blacklist', 'domain'] });
    else queryClient.invalidateQueries({ queryKey: ['whitelist', 'ip'] });
  };

  const addMutation = useMutation({
    mutationFn: (vars: { endpoint: string; payload: Record<string, string> }) =>
      api.post(vars.endpoint, vars.payload),
    onSuccess: () => {
      toast.success('Rule added successfully');
      setNewItem('');
      setNewDesc('');
      setIsAdding(false);
      invalidateActive();
    },
    onError: (err) => toast.error(getErrorMessage(err, 'Failed to add rule')),
  });

  const deleteMutation = useMutation({
    mutationFn: (endpoint: string) => api.delete(endpoint),
    onSuccess: () => {
      toast.success('Rule deleted successfully');
      setPendingDeleteId(null);
      invalidateActive();
    },
    onError: (err) => toast.error(getErrorMessage(err, 'Failed to delete rule')),
  });

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newItem) return;
    let endpoint = '';
    let payload: Record<string, string> = {};
    if (activeTab === 'ip') { endpoint = 'ip-blacklist'; payload = { ip: newItem, description: newDesc }; }
    else if (activeTab === 'domain') { endpoint = 'domain-blacklist'; payload = { domain: newItem, description: newDesc }; }
    else { endpoint = 'ip-whitelist'; payload = { ip: newItem, description: newDesc }; }
    addMutation.mutate({ endpoint, payload });
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
      invalidateActive();
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to import entries'), { id: loadingToast });
    }
  };

  const handleDelete = (id: number) => {
    let endpoint = '';
    if (activeTab === 'ip') endpoint = `ip-blacklist/${id}`;
    else if (activeTab === 'domain') endpoint = `domain-blacklist/${id}`;
    else endpoint = `ip-whitelist/${id}`;
    deleteMutation.mutate(endpoint);
  };

  const handleImport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!importUrl) return;
    const loadingToast = toast.loading(`Importing ${activeTab}s from URL...`);
    try {
      const response = await api.post('blacklists/import', { type: activeTab, url: importUrl });
      toast.success(`Imported ${response.data.data?.added || 0} rules successfully`, { id: loadingToast });
      setImportUrl('');
      setIsImporting(false);
      invalidateActive();
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to import rules'), { id: loadingToast });
    }
  };

  const handleGeoBlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!geoCountry) return;
    const countries = geoCountry.split(/[\s,]+/).map(c => c.trim().toUpperCase()).filter(c => c.length === 2);
    if (countries.length === 0) return;
    const loadingToast = toast.loading(`Importing IP blocks for ${countries.join(', ')}...`);
    try {
      const response = await api.post('blacklists/import-geo', { countries });
      toast.success(`Imported ${response.data.data?.imported || 0} IPs successfully`, { id: loadingToast });
      setGeoCountry('');
      setIsGeoBlocking(false);
      queryClient.invalidateQueries({ queryKey: ['blacklist', 'ip'] });
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to import GeoIP blocks'), { id: loadingToast });
    }
  };

  const handlePopularListImport = async (listUrl: string, listName: string) => {
    setImportingList(listName);
    const loadingToast = toast.loading(`Downloading ${listName}...`);
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
      invalidateActive();
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

  const closeAllPanels = (except?: string) => {
    if (except !== 'add') setIsAdding(false);
    if (except !== 'bulk') setIsBulkAdding(false);
    if (except !== 'import') setIsImporting(false);
    if (except !== 'geo') setIsGeoBlocking(false);
    if (except !== 'popular') setIsPopularLists(false);
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
            <button onClick={() => { closeAllPanels('geo'); setIsGeoBlocking(!isGeoBlocking); }}
              className={`flex items-center px-4 py-2 rounded-md text-sm font-medium transition-colors ${isGeoBlocking ? 'bg-primary/20 text-primary' : 'bg-secondary text-secondary-foreground hover:bg-secondary/80'}`}>
              <Map className="w-4 h-4 mr-2" />Geo-Block
            </button>
          )}
          {activeTab !== 'whitelist' && (
            <button type="button" onClick={() => { closeAllPanels('popular'); setIsPopularLists(!isPopularLists); }}
              className={`flex items-center px-4 py-2 rounded-md text-sm font-medium transition-colors ${isPopularLists ? 'bg-primary/20 text-primary' : 'bg-secondary text-secondary-foreground hover:bg-secondary/80'}`}>
              <Database className="w-4 h-4 mr-2" />Popular Lists
            </button>
          )}
          {activeTab !== 'whitelist' && (
            <button type="button" onClick={() => { closeAllPanels('import'); setIsImporting(!isImporting); }}
              className={`flex items-center px-4 py-2 rounded-md text-sm font-medium transition-colors ${isImporting ? 'bg-primary/20 text-primary' : 'bg-secondary text-secondary-foreground hover:bg-secondary/80'}`}>
              <Download className="w-4 h-4 mr-2" />Import URL
            </button>
          )}
          <button type="button" onClick={() => { closeAllPanels('bulk'); setIsBulkAdding(!isBulkAdding); }}
            className={`flex items-center px-4 py-2 rounded-md text-sm font-medium transition-colors ${isBulkAdding ? 'bg-primary/20 text-primary' : 'bg-secondary text-secondary-foreground hover:bg-secondary/80'}`}>
            <Plus className="w-4 h-4 mr-2" />Bulk Add
          </button>
          <button onClick={() => { closeAllPanels('add'); setIsAdding(!isAdding); }}
            className={`flex items-center px-4 py-2 rounded-md text-sm font-medium transition-colors ${isAdding ? 'bg-destructive/90 text-destructive-foreground' : 'bg-primary text-primary-foreground hover:bg-primary/90'}`}>
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
                <label className="text-sm font-medium">{activeTab === 'ip' ? 'IP Address' : activeTab === 'domain' ? 'Domain' : 'IP / CIDR Network'}</label>
                <input type="text" value={newItem} onChange={(e) => setNewItem(e.target.value)}
                  placeholder={activeTab === 'ip' ? 'e.g. 192.168.1.100' : activeTab === 'domain' ? 'e.g. bad-domain.com' : 'e.g. 192.168.0.0/16'}
                  className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary" required />
              </div>
              <div className="flex-1 space-y-2">
                <label className="text-sm font-medium">Description (Optional)</label>
                <input type="text" value={newDesc} onChange={(e) => setNewDesc(e.target.value)} placeholder="Why is this blocked?"
                  className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary" />
              </div>
              <button type="submit" className="px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 transition-colors h-10">Save Rule</button>
            </form>
          </CardContent>
        </Card>
      )}

      {isBulkAdding && (
        <Card className="bg-card/50 border-primary/50">
          <CardContent className="pt-6">
            <form onSubmit={handleBulkAdd} className="space-y-3">
              <div className="space-y-2">
                <label className="text-sm font-medium">{activeTab === 'domain' ? 'Domains' : 'IP Addresses / CIDR Networks'} — one per line</label>
                <textarea value={bulkText} onChange={(e) => setBulkText(e.target.value)}
                  placeholder={activeTab === 'domain' ? 'bad-domain.com\nanother-domain.net' : '192.168.1.100\n10.0.0.0/8'}
                  rows={6} className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-primary resize-y" required />
              </div>
              <p className="text-xs text-muted-foreground">Lines starting with # are ignored. Invalid entries are skipped.</p>
              <div className="flex gap-2">
                <button type="submit" className="px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 transition-colors">Add All</button>
                <button type="button" onClick={() => setIsBulkAdding(false)} className="px-4 py-2 bg-secondary text-secondary-foreground rounded-md text-sm font-medium hover:bg-secondary/80 transition-colors">Cancel</button>
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
                <input type="url" value={importUrl} onChange={(e) => setImportUrl(e.target.value)} placeholder="https://raw.githubusercontent.com/..."
                  className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary" required />
              </div>
              <button type="submit" className="px-4 py-2 bg-secondary text-secondary-foreground rounded-md text-sm font-medium hover:bg-secondary/80 transition-colors h-10">Import List</button>
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
                <button onClick={() => handlePopularListImport(list.url, list.name)} disabled={importingList !== null}
                  className="w-full flex items-center justify-center px-4 py-2 bg-secondary text-secondary-foreground rounded-md text-sm font-medium hover:bg-secondary/80 transition-colors mt-auto disabled:opacity-60 disabled:cursor-not-allowed">
                  {importingList === list.name ? (<><Loader2 className="w-4 h-4 mr-2 animate-spin" />Importing...</>) : (<><Download className="w-4 h-4 mr-2" />Import List</>)}
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
                <input type="text" value={geoCountry} onChange={(e) => setGeoCountry(e.target.value.toUpperCase())} placeholder="e.g. CN, RU, KP"
                  className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary" required />
              </div>
              <button type="submit" className="px-4 py-2 bg-secondary text-secondary-foreground rounded-md text-sm font-medium hover:bg-secondary/80 transition-colors h-10">Download & Block IPs</button>
            </form>
            <p className="text-xs text-muted-foreground mt-3">Fetches all known IPv4 blocks for each country and adds them to your IP Blacklist. Use 2-letter ISO codes: CN, RU, KP, IR...</p>
          </CardContent>
        </Card>
      )}

      <div className="flex space-x-1 bg-card/50 p-1 rounded-lg w-fit border border-border">
        <button onClick={() => setActiveTab('ip')}
          className={`flex items-center px-4 py-2 rounded-md text-sm font-medium transition-colors ${activeTab === 'ip' ? 'bg-[#1f1f1f] text-white shadow-sm' : 'text-muted-foreground hover:text-white'}`}>
          <Server className="w-4 h-4 mr-2" />IP Addresses
          <span className="ml-2 bg-secondary text-xs px-2 py-0.5 rounded-full">{ipResult?.total ?? 0}</span>
        </button>
        <button onClick={() => setActiveTab('domain')}
          className={`flex items-center px-4 py-2 rounded-md text-sm font-medium transition-colors ${activeTab === 'domain' ? 'bg-[#1f1f1f] text-white shadow-sm' : 'text-muted-foreground hover:text-white'}`}>
          <Globe className="w-4 h-4 mr-2" />Domains
          <span className="ml-2 bg-secondary text-xs px-2 py-0.5 rounded-full">{domainResult?.total ?? 0}</span>
        </button>
        <button type="button" onClick={() => { setActiveTab('whitelist'); closeAllPanels(); }}
          className={`flex items-center px-4 py-2 rounded-md text-sm font-medium transition-colors ${activeTab === 'whitelist' ? 'bg-green-500/20 text-green-500 shadow-sm' : 'text-muted-foreground hover:text-green-500'}`}>
          <CheckCircle className="w-4 h-4 mr-2" />IP Whitelist
          <span className="ml-2 bg-secondary text-xs px-2 py-0.5 rounded-full">{whitelists.length}</span>
        </button>
      </div>

      {/* Search bar */}
      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-sm">
          <input
            type="text"
            placeholder={`Search ${activeTab === 'domain' ? 'domains' : 'IPs'}...`}
            value={searchTerm}
            onChange={(e) => { setSearchTerm(e.target.value); resetPage(); }}
            className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary pl-9"
          />
          <Ban className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
        </div>
        <span className="text-sm text-muted-foreground">
          {activeTotal.toLocaleString()} total | Page {page + 1}/{Math.max(totalPages, 1)}
        </span>
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

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <button
            onClick={() => setPage(0)}
            disabled={page === 0}
            className="px-3 py-1.5 text-sm rounded-md bg-secondary hover:bg-secondary/80 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            First
          </button>
          <button
            onClick={() => setPage(p => Math.max(0, p - 1))}
            disabled={page === 0}
            className="px-3 py-1.5 text-sm rounded-md bg-secondary hover:bg-secondary/80 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Prev
          </button>
          <span className="text-sm text-muted-foreground px-3">
            Page {page + 1} of {totalPages}
          </span>
          <button
            onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
            disabled={page >= totalPages - 1}
            className="px-3 py-1.5 text-sm rounded-md bg-secondary hover:bg-secondary/80 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Next
          </button>
          <button
            onClick={() => setPage(totalPages - 1)}
            disabled={page >= totalPages - 1}
            className="px-3 py-1.5 text-sm rounded-md bg-secondary hover:bg-secondary/80 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Last
          </button>
        </div>
      )}
    </div>
  );
}
