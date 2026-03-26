import { Card, CardContent } from '../components/ui/card';
import { api } from '../lib/api';
import { Search, RefreshCw, FileText, Trash2, Activity, ShieldAlert, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { useState, useEffect, useRef, useMemo } from 'react';
import toast from 'react-hot-toast';
import { useQuery } from '@tanstack/react-query';
import type { LogEntry, LogsPageData } from '../types';

export function Logs() {
  const [searchTerm, setSearchTerm] = useState('');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [realtimeLogs, setRealtimeLogs] = useState<LogEntry[]>([]);
  const socketRef = useRef<WebSocket | null>(null);

  const { data, isLoading: loading, refetch: refreshLogs } = useQuery<LogsPageData>({
    queryKey: ['logs', 'page'],
    queryFn: () => api.get('logs?limit=100').then(r => r.data),
  });

  // Initialize logs from API
  useEffect(() => {
    if (data?.data) {
      setRealtimeLogs(data.data);
    } else if (data?.logs) {
      setRealtimeLogs(data.logs);
    }
  }, [data]);

  // Setup WebSocket connection for real-time logs
  // Fetches a one-time auth token first since browsers cannot send auth headers on WS upgrades
  useEffect(() => {
    if (!autoRefresh) {
      if (socketRef.current) {
        socketRef.current.close();
        socketRef.current = null;
      }
      return;
    }

    let ws: WebSocket | null = null;
    let pingInterval: ReturnType<typeof setInterval>;
    let cancelled = false;

    api.get('/ws-token').then(({ data }) => {
      if (cancelled) return;

      const token = data.token;
      const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const hostname = window.location.hostname;
      // WS port resolution order:
      //  1. window.__WS_BACKEND_PORT__  (runtime injection via <script> in index.html)
      //  2. VITE_WS_BACKEND_PORT        (build-time env var, e.g. for direct-port deployments)
      //  3. window.location.port        (same port as UI — works when nginx proxies /api/ws/)
      //  4. protocol default (443/80)
      const wsPort = (window as Window & { __WS_BACKEND_PORT__?: string }).__WS_BACKEND_PORT__
        ?? import.meta.env.VITE_WS_BACKEND_PORT
        ?? window.location.port
        ?? (window.location.protocol === 'https:' ? '443' : '80');
      const socketUrl = `${wsProtocol}//${hostname}:${wsPort}/api/ws/logs?token=${encodeURIComponent(token)}`;

      ws = new WebSocket(socketUrl);
      socketRef.current = ws;

      ws.onopen = () => {
        console.log('Connected to real-time log stream');
        pingInterval = setInterval(() => {
          if (ws?.readyState === WebSocket.OPEN) {
            ws.send('ping');
          }
        }, 30000);
      };

      ws.onmessage = (event) => {
        if (event.data === 'pong') return;
        try {
          const newLog = JSON.parse(event.data);
          setRealtimeLogs(prev => [newLog, ...prev].slice(0, 200));
        } catch (e) {
          console.error('Failed to parse incoming log', e);
        }
      };

      ws.onclose = () => {
        console.log('Disconnected from real-time log stream');
        if (pingInterval) clearInterval(pingInterval);
      };

      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
      };
    }).catch((err) => {
      console.error('Failed to obtain WS token:', err);
    });

    return () => {
      cancelled = true;
      if (pingInterval) clearInterval(pingInterval);
      if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
        ws.close();
      }
    };
  }, [autoRefresh]);

  // Filter logs based on search
  const filteredLogs = realtimeLogs.filter((log) =>
    log.destination?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    log.client_ip?.includes(searchTerm) ||
    log.status?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Compute stats from current logs
  const stats = useMemo(() => {
    const total = realtimeLogs.length;
    const blocked = realtimeLogs.filter((l) =>
      l.status?.includes('DENIED') ||
      l.status?.includes('403') ||
      l.destination?.includes('blocked')
    ).length;
    const errors = realtimeLogs.filter((l) =>
      l.status?.includes('500') ||
      l.status?.includes('502') ||
      l.status?.includes('503') ||
      l.status?.includes('504') ||
      (l.status?.includes('ERR_') && !l.status?.includes('ERR_ACCESS_DENIED'))
    ).length;
    const success = total - blocked - errors;
    
    return { total, blocked, errors, success };
  }, [realtimeLogs]);

  const [clearPending, setClearPending] = useState(false);

  const handleClearLogs = async () => {
    if (!clearPending) { setClearPending(true); return; }
    setClearPending(false);
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
          {clearPending ? (
            <div className="flex items-center gap-1">
              <button
                type="button"
                onClick={handleClearLogs}
                className="px-3 py-2 bg-destructive text-destructive-foreground rounded-md text-sm font-medium hover:bg-destructive/90 transition-colors"
              >
                Confirm Clear
              </button>
              <button
                type="button"
                onClick={() => setClearPending(false)}
                className="px-3 py-2 bg-secondary text-foreground rounded-md text-sm font-medium hover:bg-secondary/80 transition-colors"
              >
                Cancel
              </button>
            </div>
          ) : (
            <button
              type="button"
              onClick={handleClearLogs}
              className="flex items-center px-3 py-2 bg-destructive/10 text-destructive rounded-md text-sm font-medium hover:bg-destructive/20 transition-colors"
            >
              <Trash2 className="w-4 h-4 mr-2" />
              Clear All
            </button>
          )}
        </div>
      </div>
      
      {/* Quick Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-muted-foreground">Total Requests</p>
              <h3 className="text-2xl font-bold">{stats.total}</h3>
            </div>
            <div className="p-3 bg-primary/10 rounded-full text-primary">
              <Activity className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-muted-foreground">Success</p>
              <h3 className="text-2xl font-bold text-green-500">{stats.success}</h3>
            </div>
            <div className="p-3 bg-green-500/10 rounded-full text-green-500">
              <CheckCircle2 className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-muted-foreground">Blocked</p>
              <h3 className="text-2xl font-bold text-orange-500">{stats.blocked}</h3>
            </div>
            <div className="p-3 bg-orange-500/10 rounded-full text-orange-500">
              <ShieldAlert className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-muted-foreground">Errors</p>
              <h3 className="text-2xl font-bold text-red-500">{stats.errors}</h3>
            </div>
            <div className="p-3 bg-red-500/10 rounded-full text-red-500">
              <AlertTriangle className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>
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
                {filteredLogs.map((log) => (
                  <tr key={log.id ?? log.timestamp} className="hover:bg-secondary/20 transition-colors font-mono text-xs">
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
                        log.status?.includes('DENIED') || log.status?.includes('403')
                          ? 'bg-destructive/10 text-destructive border-destructive/20'
                          : 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'
                      }`}>
                        {log.status ?? '-'}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-right text-muted-foreground">
                      {log.bytes != null ? `${(log.bytes / 1024).toFixed(1)} KB` : '-'}
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