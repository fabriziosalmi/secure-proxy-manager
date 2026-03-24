import { Card, CardContent } from '../components/ui/card';
import { useApi } from '../hooks/useApi';
import { api } from '../lib/api';
import { Search, RefreshCw, FileText, Trash2, Activity } from 'lucide-react';
import { useState, useEffect, useRef } from 'react';
import toast from 'react-hot-toast';

export function Logs() {
  const [searchTerm, setSearchTerm] = useState('');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [realtimeLogs, setRealtimeLogs] = useState<any[]>([]);
  const { data, loading, execute: refreshLogs } = useApi<any>('logs?limit=100');
  const socketRef = useRef<WebSocket | null>(null);

  // Initialize logs from API
  useEffect(() => {
    if (data?.logs) {
      setRealtimeLogs(data.logs);
    }
  }, [data]);

  // Setup native WebSocket connection for real-time logs (migrated from Socket.IO to FastAPI native WS)
  useEffect(() => {
    if (autoRefresh) {
      const backendUrl = import.meta.env.VITE_API_URL || window.location.origin;
      // Convert http/https to ws/wss for WebSocket URL
      const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsHost = backendUrl.replace(/^https?:\/\//, '');
      const socketUrl = `${wsProtocol}//${wsHost}/ws/logs`;
      
      const ws = new WebSocket(socketUrl);
      socketRef.current = ws as any; // Cast for now, would need a proper ref type

      ws.onopen = () => {
        console.log('Connected to real-time log stream via FastAPI WebSocket');
        // Keep alive ping
        setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send('ping');
          }
        }, 30000);
      };

      ws.onmessage = (event) => {
        if (event.data === 'pong') return;
        try {
          const newLog = JSON.parse(event.data);
          setRealtimeLogs(prev => [newLog, ...prev].slice(0, 200)); // Keep last 200 logs
        } catch (e) {
          console.error('Failed to parse incoming log', e);
        }
      };

      ws.onclose = () => {
        console.log('Disconnected from real-time log stream');
      };
      
      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
      };

      return () => {
        if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
          ws.close();
        }
      };
    } else {
      if (socketRef.current) {
        (socketRef.current as any).close();
      }
    }
  }, [autoRefresh]);

  // Filter logs based on search
  const filteredLogs = realtimeLogs.filter((log: any) => 
    log.destination?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    log.client_ip?.includes(searchTerm) ||
    log.status?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleClearLogs = async () => {
    if (!confirm('Are you sure you want to clear all logs?')) return;
    const loadingToast = toast.loading('Clearing logs...');
    try {
      await api.post('logs/clear');
      toast.success('Logs cleared successfully', { id: loadingToast });
      setRealtimeLogs([]);
      refreshLogs();
    } catch (err) {
      toast.error('Failed to clear logs', { id: loadingToast });
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Access Logs</h1>
          <p className="text-muted-foreground">Monitor real-time proxy traffic</p>
        </div>
        <div className="flex items-center space-x-2">
          <button 
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center px-3 py-2 rounded-md text-sm font-medium transition-colors ${autoRefresh ? 'bg-primary/20 text-primary' : 'bg-secondary text-foreground hover:bg-secondary/80'}`}
          >
            <Activity className={`w-4 h-4 mr-2 ${autoRefresh ? 'animate-pulse' : ''}`} />
            Live Stream
          </button>
          <button 
            onClick={() => refreshLogs()}
            className="flex items-center px-3 py-2 bg-secondary text-foreground rounded-md text-sm font-medium hover:bg-secondary/80 transition-colors"
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${loading && !autoRefresh ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button 
            onClick={handleClearLogs}
            className="flex items-center px-3 py-2 bg-destructive/10 text-destructive rounded-md text-sm font-medium hover:bg-destructive/20 transition-colors"
          >
            <Trash2 className="w-4 h-4 mr-2" />
            Clear All
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
          <div className="ml-auto text-sm text-muted-foreground">
            Showing {filteredLogs.length} entries
          </div>
        </div>
        <CardContent className="p-0">
          <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
            <table className="w-full text-sm text-left relative">
              <thead className="text-xs text-muted-foreground uppercase bg-secondary/80 border-b border-border sticky top-0 backdrop-blur-sm z-10">
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
                {filteredLogs.map((log: any, i: number) => (
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

                {filteredLogs.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-6 py-12 text-center text-muted-foreground">
                      <FileText className="w-8 h-8 mx-auto mb-3 opacity-20" />
                      No logs match your search
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