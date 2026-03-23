import { Card, CardContent } from '../components/ui/card';
import { useApi } from '../hooks/useApi';
import { Search, Filter, RefreshCw, FileText } from 'lucide-react';
import { useState } from 'react';

export function Logs() {
  const [searchTerm, setSearchTerm] = useState('');
  const { data, loading, execute: refreshLogs } = useApi<any>('logs?limit=50');
  const logs = data?.logs || [];

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Access Logs</h1>
          <p className="text-muted-foreground">Monitor real-time proxy traffic</p>
        </div>
        <div className="flex items-center space-x-2">
          <button 
            onClick={() => refreshLogs()}
            className="flex items-center px-3 py-2 bg-secondary text-foreground rounded-md text-sm font-medium hover:bg-secondary/80 transition-colors"
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button className="flex items-center px-3 py-2 bg-secondary text-foreground rounded-md text-sm font-medium hover:bg-secondary/80 transition-colors">
            <Filter className="w-4 h-4 mr-2" />
            Filter
          </button>
        </div>
      </div>

      <Card className="bg-card/50">
        <div className="p-4 border-b border-border flex items-center">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input 
              type="text" 
              placeholder="Search by IP, domain, or status..." 
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-background border border-border rounded-md pl-9 pr-4 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-all"
            />
          </div>
        </div>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead className="text-xs text-muted-foreground uppercase bg-secondary/50 border-b border-border">
                <tr>
                  <th className="px-6 py-4 font-medium">Timestamp</th>
                  <th className="px-6 py-4 font-medium">Client IP</th>
                  <th className="px-6 py-4 font-medium">Method</th>
                  <th className="px-6 py-4 font-medium">Destination</th>
                  <th className="px-6 py-4 font-medium">Status</th>
                  <th className="px-6 py-4 font-medium text-right">Size</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {logs.map((log: any, i: number) => (
                  <tr key={i} className="hover:bg-secondary/20 transition-colors font-mono text-xs">
                    <td className="px-6 py-3 text-muted-foreground whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="px-6 py-3 text-white">{log.client_ip}</td>
                    <td className="px-6 py-3 text-primary">{log.method}</td>
                    <td className="px-6 py-3 text-muted-foreground truncate max-w-xs" title={log.destination}>
                      {log.destination}
                    </td>
                    <td className="px-6 py-3">
                      <span className={`px-2 py-1 rounded-full text-[10px] font-medium border ${
                        log.status.includes('DENIED') || log.status.includes('403')
                          ? 'bg-destructive/10 text-destructive border-destructive/20' 
                          : 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'
                      }`}>
                        {log.status}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-right text-muted-foreground">
                      {(log.bytes / 1024).toFixed(1)} KB
                    </td>
                  </tr>
                ))}

                {logs.length === 0 && !loading && (
                  <tr>
                    <td colSpan={6} className="px-6 py-12 text-center text-muted-foreground">
                      <FileText className="w-8 h-8 mx-auto mb-3 opacity-20" />
                      No logs available
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}