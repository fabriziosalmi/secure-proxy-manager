import React, { useState, useEffect } from 'react';
import { ArrowUpIcon, ArrowDownIcon, ShieldCheckIcon, XCircleIcon } from '@heroicons/react/24/outline';
import { Chart as ChartJS, ArcElement, CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend } from 'chart.js';
import { Pie, Line } from 'react-chartjs-2';

// Register ChartJS components
ChartJS.register(ArcElement, CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend);

const Dashboard = () => {
  // Mock data for demonstration purposes
  const [stats, setStats] = useState({
    activeConnections: 36,
    blockedRequests: 428,
    totalTraffic: '2.7',
    cacheHitRatio: 67
  });

  const [trafficData, setTrafficData] = useState({
    labels: ['00:00', '03:00', '06:00', '09:00', '12:00', '15:00', '18:00', '21:00'],
    datasets: [
      {
        label: 'Traffic (MB)',
        data: [65, 59, 80, 81, 56, 55, 40, 70],
        fill: false,
        borderColor: 'rgb(75, 192, 192)',
        tension: 0.1
      }
    ]
  });

  const [contentTypeData, setContentTypeData] = useState({
    labels: ['HTML', 'Images', 'JavaScript', 'CSS', 'Other'],
    datasets: [
      {
        label: 'Content Types',
        data: [12, 19, 3, 5, 2],
        backgroundColor: [
          'rgba(255, 99, 132, 0.5)',
          'rgba(54, 162, 235, 0.5)',
          'rgba(255, 206, 86, 0.5)',
          'rgba(75, 192, 192, 0.5)',
          'rgba(153, 102, 255, 0.5)',
        ],
        borderWidth: 1,
      },
    ],
  });

  // Simulate fetching data
  useEffect(() => {
    // In a real application, we would fetch data from the API here
    const interval = setInterval(() => {
      // Simulate data updates
      setStats(prev => ({
        ...prev,
        activeConnections: Math.floor(Math.random() * 50) + 10,
      }));
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-semibold text-gray-900">Proxy Overview</h2>
      
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        {/* Active Connections */}
        <div className="card">
          <h3 className="text-lg font-medium text-gray-900">Active Connections</h3>
          <div className="mt-2 flex items-center justify-between">
            <span className="text-3xl font-semibold">{stats.activeConnections}</span>
            <ArrowUpIcon className="h-5 w-5 text-green-500" />
          </div>
        </div>

        {/* Blocked Requests */}
        <div className="card">
          <h3 className="text-lg font-medium text-gray-900">Blocked Requests</h3>
          <div className="mt-2 flex items-center justify-between">
            <span className="text-3xl font-semibold">{stats.blockedRequests}</span>
            <ShieldCheckIcon className="h-6 w-6 text-primary-600" />
          </div>
        </div>

        {/* Total Traffic */}
        <div className="card">
          <h3 className="text-lg font-medium text-gray-900">Total Traffic</h3>
          <div className="mt-2 flex items-center justify-between">
            <span className="text-3xl font-semibold">{stats.totalTraffic} GB</span>
            <ArrowDownIcon className="h-5 w-5 text-indigo-500" />
          </div>
        </div>

        {/* Cache Hit Ratio */}
        <div className="card">
          <h3 className="text-lg font-medium text-gray-900">Cache Hit Ratio</h3>
          <div className="mt-2 flex items-center justify-between">
            <span className="text-3xl font-semibold">{stats.cacheHitRatio}%</span>
            <XCircleIcon className="h-6 w-6 text-yellow-500" />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        {/* Traffic Over Time */}
        <div className="card">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Traffic Over Time</h3>
          <div className="h-64">
            <Line 
              data={trafficData} 
              options={{
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                  y: {
                    beginAtZero: true,
                    title: {
                      display: true,
                      text: 'MB'
                    }
                  }
                }
              }} 
            />
          </div>
        </div>

        {/* Content Types */}
        <div className="card">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Content Types</h3>
          <div className="h-64 flex items-center justify-center">
            <Pie 
              data={contentTypeData} 
              options={{
                responsive: true,
                maintainAspectRatio: false,
              }} 
            />
          </div>
        </div>
      </div>

      <div className="card">
        <h3 className="text-lg font-medium text-gray-900 mb-4">System Status</h3>
        <div className="overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Service</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Uptime</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Check</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              <tr>
                <td className="px-6 py-4 whitespace-nowrap">Squid Proxy</td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">Active</span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">3d 5h 12m</td>
                <td className="px-6 py-4 whitespace-nowrap">Just now</td>
              </tr>
              <tr>
                <td className="px-6 py-4 whitespace-nowrap">Blacklist Service</td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">Active</span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">3d 5h 10m</td>
                <td className="px-6 py-4 whitespace-nowrap">1 minute ago</td>
              </tr>
              <tr>
                <td className="px-6 py-4 whitespace-nowrap">Authentication</td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">Active</span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">3d 5h 12m</td>
                <td className="px-6 py-4 whitespace-nowrap">5 minutes ago</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;