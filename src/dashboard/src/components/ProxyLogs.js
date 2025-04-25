import React, { useState, useEffect } from 'react';
import { MagnifyingGlassIcon, ArrowDownTrayIcon } from '@heroicons/react/24/outline';

const ProxyLogs = () => {
  const [logs, setLogs] = useState([]);
  const [filteredLogs, setFilteredLogs] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [logType, setLogType] = useState('access');
  const [isLoading, setIsLoading] = useState(true);
  const [dateRange, setDateRange] = useState('today');

  // Simulated log data
  const mockAccessLogs = [
    { id: 1, timestamp: '2025-04-25 08:12:31', ip: '192.168.1.45', request: 'GET', url: 'https://example.com/index.html', status: 200, size: '1.2 KB' },
    { id: 2, timestamp: '2025-04-25 08:12:45', ip: '192.168.1.45', request: 'GET', url: 'https://example.com/style.css', status: 200, size: '4.5 KB' },
    { id: 3, timestamp: '2025-04-25 08:13:02', ip: '192.168.1.46', request: 'GET', url: 'https://malware-domain.com', status: 403, size: '0.2 KB' },
    { id: 4, timestamp: '2025-04-25 08:13:15', ip: '192.168.1.47', request: 'POST', url: 'https://api.example.com/login', status: 200, size: '0.5 KB' },
    { id: 5, timestamp: '2025-04-25 08:14:03', ip: '192.168.1.48', request: 'GET', url: 'https://cdn.example.com/image.png', status: 200, size: '245 KB' },
    { id: 6, timestamp: '2025-04-25 08:15:22', ip: '192.168.1.45', request: 'GET', url: 'https://example.com/favicon.ico', status: 304, size: '0 KB' },
    { id: 7, timestamp: '2025-04-25 08:16:47', ip: '192.168.1.49', request: 'GET', url: 'https://phishing-site.net', status: 403, size: '0.2 KB' },
    { id: 8, timestamp: '2025-04-25 08:17:12', ip: '192.168.1.50', request: 'GET', url: 'https://example.org/about.html', status: 200, size: '3.7 KB' },
    { id: 9, timestamp: '2025-04-25 08:18:05', ip: '192.168.1.51', request: 'GET', url: 'https://example.org/script.js', status: 200, size: '12.4 KB' },
    { id: 10, timestamp: '2025-04-25 08:19:31', ip: '192.168.1.52', request: 'POST', url: 'https://api.example.org/data', status: 500, size: '0.3 KB' },
  ];

  const mockCacheLogs = [
    { id: 1, timestamp: '2025-04-25 08:12:31', operation: 'CREATE', url: 'https://example.com/index.html', result: 'MISS' },
    { id: 2, timestamp: '2025-04-25 08:12:45', operation: 'CREATE', url: 'https://example.com/style.css', result: 'MISS' },
    { id: 3, timestamp: '2025-04-25 08:14:03', operation: 'CREATE', url: 'https://cdn.example.com/image.png', result: 'MISS' },
    { id: 4, timestamp: '2025-04-25 08:15:22', operation: 'READ', url: 'https://example.com/favicon.ico', result: 'HIT' },
    { id: 5, timestamp: '2025-04-25 08:17:12', operation: 'READ', url: 'https://example.org/about.html', result: 'MISS' },
    { id: 6, timestamp: '2025-04-25 08:18:05', operation: 'CREATE', url: 'https://example.org/script.js', result: 'MISS' },
    { id: 7, timestamp: '2025-04-25 08:20:45', operation: 'READ', url: 'https://example.com/index.html', result: 'HIT' },
    { id: 8, timestamp: '2025-04-25 08:21:12', operation: 'READ', url: 'https://example.com/style.css', result: 'HIT' },
    { id: 9, timestamp: '2025-04-25 08:22:37', operation: 'UPDATE', url: 'https://cdn.example.com/image.png', result: 'HIT' },
    { id: 10, timestamp: '2025-04-25 08:24:18', operation: 'READ', url: 'https://example.org/script.js', result: 'HIT' },
  ];

  useEffect(() => {
    // Simulate API fetch
    setIsLoading(true);
    setTimeout(() => {
      setLogs(logType === 'access' ? mockAccessLogs : mockCacheLogs);
      setIsLoading(false);
    }, 800);
  }, [logType]);

  useEffect(() => {
    // Apply search filter
    if (searchTerm) {
      const filtered = logs.filter(log => {
        // Access logs
        if (logType === 'access') {
          return (
            log.url.toLowerCase().includes(searchTerm.toLowerCase()) ||
            log.ip.includes(searchTerm) ||
            log.request.toLowerCase().includes(searchTerm.toLowerCase()) ||
            log.status.toString().includes(searchTerm)
          );
        }
        // Cache logs
        else {
          return (
            log.url.toLowerCase().includes(searchTerm.toLowerCase()) ||
            log.operation.toLowerCase().includes(searchTerm.toLowerCase()) ||
            log.result.toLowerCase().includes(searchTerm.toLowerCase())
          );
        }
      });
      setFilteredLogs(filtered);
    } else {
      setFilteredLogs(logs);
    }
  }, [logs, searchTerm, logType]);

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-semibold text-gray-900">Proxy Logs</h2>
        <button className="btn btn-secondary flex items-center">
          <ArrowDownTrayIcon className="h-5 w-5 mr-2" />
          Export Logs
        </button>
      </div>

      <div className="card">
        <div className="mb-6 flex flex-col md:flex-row space-y-4 md:space-y-0 md:space-x-4">
          <div className="md:w-1/3">
            <label htmlFor="log-type" className="block text-sm font-medium text-gray-700 mb-1">Log Type</label>
            <select
              id="log-type"
              value={logType}
              onChange={(e) => setLogType(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-primary-500 focus:border-primary-500"
            >
              <option value="access">Access Logs</option>
              <option value="cache">Cache Logs</option>
            </select>
          </div>

          <div className="md:w-1/3">
            <label htmlFor="date-range" className="block text-sm font-medium text-gray-700 mb-1">Date Range</label>
            <select
              id="date-range"
              value={dateRange}
              onChange={(e) => setDateRange(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-primary-500 focus:border-primary-500"
            >
              <option value="today">Today</option>
              <option value="yesterday">Yesterday</option>
              <option value="week">Last 7 Days</option>
              <option value="month">Last 30 Days</option>
            </select>
          </div>

          <div className="md:w-1/3">
            <label htmlFor="search" className="block text-sm font-medium text-gray-700 mb-1">Search</label>
            <div className="relative rounded-md shadow-sm">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <MagnifyingGlassIcon className="h-5 w-5 text-gray-400" />
              </div>
              <input
                type="text"
                id="search"
                className="focus:ring-primary-500 focus:border-primary-500 block w-full pl-10 sm:text-sm border-gray-300 rounded-md py-2 border"
                placeholder="Search logs..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
          </div>
        </div>

        {isLoading ? (
          <div className="flex justify-center py-10">
            <svg className="animate-spin h-8 w-8 text-primary-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  {logType === 'access' ? (
                    <>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Timestamp</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">IP Address</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Request</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">URL</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Size</th>
                    </>
                  ) : (
                    <>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Timestamp</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Operation</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">URL</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Result</th>
                    </>
                  )}
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredLogs.length > 0 ? (
                  filteredLogs.map((log) => (
                    <tr key={log.id} className={log.status === 403 || log.status === 500 ? 'bg-red-50' : ''}>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{log.timestamp}</td>
                      {logType === 'access' ? (
                        <>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{log.ip}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{log.request}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 max-w-xs truncate">{log.url}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm">
                            <span 
                              className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                                log.status >= 200 && log.status < 300 ? 'bg-green-100 text-green-800' :
                                log.status >= 300 && log.status < 400 ? 'bg-yellow-100 text-yellow-800' :
                                'bg-red-100 text-red-800'
                              }`}
                            >
                              {log.status}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{log.size}</td>
                        </>
                      ) : (
                        <>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{log.operation}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 max-w-xs truncate">{log.url}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm">
                            <span 
                              className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                                log.result === 'HIT' ? 'bg-green-100 text-green-800' : 'bg-blue-100 text-blue-800'
                              }`}
                            >
                              {log.result}
                            </span>
                          </td>
                        </>
                      )}
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={logType === 'access' ? 6 : 4} className="px-6 py-4 text-center text-sm text-gray-500">
                      No logs found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default ProxyLogs;