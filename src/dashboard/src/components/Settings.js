import React, { useState, useEffect } from 'react';
import { ArrowPathIcon } from '@heroicons/react/24/outline';

const Settings = () => {
  const [settings, setSettings] = useState({
    proxyPort: 3128,
    cacheSize: 1000,
    maxObjectSize: 50,
    refreshPattern: '.*',
    enableAuth: true,
    enableSSL: true,
    logLevel: 'INFO'
  });

  const [isSaving, setIsSaving] = useState(false);
  const [saveMessage, setSaveMessage] = useState('');

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setSettings({
      ...settings,
      [name]: type === 'checkbox' ? checked : value
    });
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    setIsSaving(true);
    
    // Simulate API call to save settings
    setTimeout(() => {
      setIsSaving(false);
      setSaveMessage('Settings saved successfully');
      
      // Clear success message after 3 seconds
      setTimeout(() => {
        setSaveMessage('');
      }, 3000);
    }, 1000);
  };

  const handleRestart = () => {
    if (window.confirm('Are you sure you want to restart the proxy service?')) {
      // Simulate restarting the proxy service
      setTimeout(() => {
        alert('Proxy service restarted successfully');
      }, 2000);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-semibold text-gray-900">Proxy Settings</h2>
        <button 
          className="btn btn-secondary flex items-center" 
          onClick={handleRestart}
        >
          <ArrowPathIcon className="h-5 w-5 mr-2" />
          Restart Proxy
        </button>
      </div>

      {saveMessage && (
        <div className="p-4 bg-green-100 rounded-md">
          <p className="text-green-700">{saveMessage}</p>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="card">
          <h3 className="text-lg font-medium text-gray-900 mb-4">General Settings</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label htmlFor="proxyPort" className="block text-sm font-medium text-gray-700 mb-1">
                Proxy Port
              </label>
              <input
                type="number"
                name="proxyPort"
                id="proxyPort"
                className="px-3 py-2 border border-gray-300 rounded-md w-full"
                value={settings.proxyPort}
                onChange={handleChange}
              />
            </div>
            
            <div>
              <label htmlFor="logLevel" className="block text-sm font-medium text-gray-700 mb-1">
                Log Level
              </label>
              <select
                id="logLevel"
                name="logLevel"
                className="px-3 py-2 border border-gray-300 rounded-md w-full"
                value={settings.logLevel}
                onChange={handleChange}
              >
                <option value="DEBUG">Debug</option>
                <option value="INFO">Info</option>
                <option value="NOTICE">Notice</option>
                <option value="WARNING">Warning</option>
                <option value="ERROR">Error</option>
              </select>
            </div>
          </div>
        </div>

        <div className="card">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Cache Settings</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label htmlFor="cacheSize" className="block text-sm font-medium text-gray-700 mb-1">
                Cache Size (MB)
              </label>
              <input
                type="number"
                name="cacheSize"
                id="cacheSize"
                className="px-3 py-2 border border-gray-300 rounded-md w-full"
                value={settings.cacheSize}
                onChange={handleChange}
              />
            </div>
            
            <div>
              <label htmlFor="maxObjectSize" className="block text-sm font-medium text-gray-700 mb-1">
                Maximum Object Size (MB)
              </label>
              <input
                type="number"
                name="maxObjectSize"
                id="maxObjectSize"
                className="px-3 py-2 border border-gray-300 rounded-md w-full"
                value={settings.maxObjectSize}
                onChange={handleChange}
              />
            </div>

            <div>
              <label htmlFor="refreshPattern" className="block text-sm font-medium text-gray-700 mb-1">
                Refresh Pattern
              </label>
              <input
                type="text"
                name="refreshPattern"
                id="refreshPattern"
                className="px-3 py-2 border border-gray-300 rounded-md w-full"
                value={settings.refreshPattern}
                onChange={handleChange}
              />
              <p className="mt-1 text-sm text-gray-500">Regular expression pattern for cache refresh rules</p>
            </div>
          </div>
        </div>

        <div className="card">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Security Settings</h3>
          
          <div className="space-y-4">
            <div className="flex items-center">
              <input
                id="enableAuth"
                name="enableAuth"
                type="checkbox"
                className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                checked={settings.enableAuth}
                onChange={handleChange}
              />
              <label htmlFor="enableAuth" className="ml-2 block text-sm text-gray-900">
                Enable Authentication
              </label>
            </div>
            
            <div className="flex items-center">
              <input
                id="enableSSL"
                name="enableSSL"
                type="checkbox"
                className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                checked={settings.enableSSL}
                onChange={handleChange}
              />
              <label htmlFor="enableSSL" className="ml-2 block text-sm text-gray-900">
                Enable SSL Inspection
              </label>
            </div>
          </div>
        </div>

        <div className="flex justify-end">
          <button
            type="submit"
            className="btn btn-primary"
            disabled={isSaving}
          >
            {isSaving ? 'Saving...' : 'Save Settings'}
          </button>
        </div>
      </form>
    </div>
  );
};

export default Settings;