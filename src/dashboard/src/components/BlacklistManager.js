import React, { useState, useEffect } from 'react';
import { PlusIcon, TrashIcon } from '@heroicons/react/24/outline';

const BlacklistManager = () => {
  const [domains, setDomains] = useState([]);
  const [newDomain, setNewDomain] = useState('');
  const [filter, setFilter] = useState('');
  const [isLoading, setIsLoading] = useState(true);

  // Simulate fetching blacklist data
  useEffect(() => {
    // In a real application, we would fetch domains from the API
    setTimeout(() => {
      setDomains([
        'malware-domain.com',
        'phishing-site.net',
        'adware-distributor.org',
        'malicious-tracker.com',
        'suspicious-downloads.net',
        'unwanted-ads.com',
        'data-harvester.net',
        'fake-login.com',
        'ransomware-host.net',
        'trojan-distributor.org'
      ]);
      setIsLoading(false);
    }, 1000);
  }, []);

  const handleAddDomain = () => {
    if (newDomain && !domains.includes(newDomain)) {
      setDomains([...domains, newDomain]);
      setNewDomain('');
      // In a real application, we would also send this to the API
    }
  };

  const handleDeleteDomain = (domain) => {
    setDomains(domains.filter(d => d !== domain));
    // In a real application, we would also send this to the API
  };

  const filteredDomains = domains.filter(domain => 
    domain.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-semibold text-gray-900">Blacklist Manager</h2>
        <div className="flex space-x-2">
          <button 
            className="btn btn-primary flex items-center" 
            onClick={() => {
              // In a real application, we would send this to the API
              alert('Blacklist saved successfully!');
            }}
          >
            Save Changes
          </button>
        </div>
      </div>

      <div className="card">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-4">
          <h3 className="text-lg font-medium text-gray-900 mb-2 md:mb-0">Blocked Domains</h3>
          <div className="flex space-x-2">
            <input
              type="text"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter domains..."
              className="px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary-500"
            />
          </div>
        </div>

        <div className="flex items-center mb-4">
          <input
            type="text"
            value={newDomain}
            onChange={(e) => setNewDomain(e.target.value)}
            placeholder="Enter a domain to block..."
            className="flex-grow px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary-500"
            onKeyPress={(e) => e.key === 'Enter' && handleAddDomain()}
          />
          <button 
            className="ml-2 btn btn-primary flex items-center" 
            onClick={handleAddDomain}
          >
            <PlusIcon className="h-5 w-5 mr-1" />
            Add
          </button>
        </div>

        {isLoading ? (
          <div className="flex justify-center py-10">
            <svg className="animate-spin h-8 w-8 text-primary-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
          </div>
        ) : (
          <div className="border border-gray-200 rounded-md overflow-hidden">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Domain</th>
                  <th scope="col" className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredDomains.length > 0 ? (
                  filteredDomains.map((domain, index) => (
                    <tr key={index}>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{domain}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                        <button 
                          className="text-red-600 hover:text-red-900"
                          onClick={() => handleDeleteDomain(domain)}
                        >
                          <TrashIcon className="h-5 w-5" />
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="2" className="px-6 py-4 text-center text-sm text-gray-500">
                      {filter ? 'No domains match your filter' : 'No domains in the blacklist'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="card">
        <h3 className="text-lg font-medium text-gray-900 mb-4">Bulk Import/Export</h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <h4 className="font-medium text-gray-800 mb-2">Import Domains</h4>
            <div className="border-dashed border-2 border-gray-300 rounded-md p-4 text-center">
              <input
                type="file"
                id="file-upload"
                className="hidden"
                accept=".txt,.csv"
              />
              <label htmlFor="file-upload" className="cursor-pointer">
                <span className="mt-2 block text-sm text-gray-600">
                  Click to upload a file (.txt or .csv)
                </span>
              </label>
            </div>
          </div>
          
          <div>
            <h4 className="font-medium text-gray-800 mb-2">Export Domains</h4>
            <button className="btn btn-secondary w-full">
              Download Blacklist
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default BlacklistManager;