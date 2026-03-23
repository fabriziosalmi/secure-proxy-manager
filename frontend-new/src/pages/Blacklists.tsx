import { Card, CardContent } from '../components/ui/card';
import { useApi } from '../hooks/useApi';
import { Ban, Globe, Server, Plus, Trash2 } from 'lucide-react';
import { useState } from 'react';

export function Blacklists() {
  const [activeTab, setActiveTab] = useState<'ip' | 'domain'>('ip');
  const { data: ipData } = useApi<any>('ip-blacklist');
  const { data: domainData } = useApi<any>('domain-blacklist');

  const ips = ipData?.blacklist || [];
  const domains = domainData?.blacklist || [];

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Blacklists</h1>
          <p className="text-muted-foreground">Manage IP and Domain blocking rules</p>
        </div>
        <button className="flex items-center px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 transition-colors">
          <Plus className="w-4 h-4 mr-2" />
          Add Rule
        </button>
      </div>

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
                    <button className="text-destructive hover:text-red-400 transition-colors p-2 rounded-md hover:bg-destructive/10">
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
                    <button className="text-destructive hover:text-red-400 transition-colors p-2 rounded-md hover:bg-destructive/10">
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