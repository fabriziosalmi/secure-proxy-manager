import React from 'react';
import { BellIcon } from '@heroicons/react/24/outline';

const Header = () => {
  return (
    <header className="bg-white shadow-sm z-10">
      <div className="px-4 sm:px-6 lg:px-8 py-4 flex justify-between items-center">
        <h1 className="text-2xl font-semibold text-gray-900">Secure Squid Proxy Dashboard</h1>
        <div className="flex items-center gap-4">
          <button className="p-1 rounded-full text-gray-500 hover:text-gray-700 focus:outline-none">
            <BellIcon className="h-6 w-6" />
          </button>
          <div className="flex items-center">
            <span className="inline-block h-8 w-8 rounded-full bg-primary-600 text-white text-center leading-8">A</span>
            <span className="ml-2 text-sm font-medium text-gray-700">Admin</span>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;