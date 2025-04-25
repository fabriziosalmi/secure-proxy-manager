// Squid Proxy Dashboard JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Elements
    const statusIndicator = document.getElementById('status-indicator');
    const statusText = document.getElementById('status-text');
    const statusDetails = document.getElementById('status-details');
    const startBtn = document.getElementById('start-btn');
    const stopBtn = document.getElementById('stop-btn');
    const restartBtn = document.getElementById('restart-btn');
    const reloadBtn = document.getElementById('reload-btn');
    const portInput = document.getElementById('port');
    const updatePortBtn = document.getElementById('update-port-btn');
    const configMessage = document.getElementById('config-message');
    
    // Security Feature Elements
    const ipBlacklistToggle = document.getElementById('ip-blacklist-toggle');
    const domainBlacklistToggle = document.getElementById('domain-blacklist-toggle');
    const directIpToggle = document.getElementById('direct-ip-toggle');
    const userAgentToggle = document.getElementById('user-agent-toggle');
    const malwareToggle = document.getElementById('malware-toggle');
    const httpsFilteringToggle = document.getElementById('https-filtering-toggle');
    const saveFeaturesBtn = document.getElementById('save-features-btn');
    const featuresMessage = document.getElementById('features-message');
    
    // IP Blacklist Tab
    const ipBlacklistTextarea = document.getElementById('ip-blacklist-textarea');
    const saveIpBlacklistBtn = document.getElementById('save-ip-blacklist-btn');
    const ipBlacklistMessage = document.getElementById('ip-blacklist-message');
    
    // Domain Blacklist Tab
    const domainBlacklistTextarea = document.getElementById('domain-blacklist-textarea');
    const saveDomainBlacklistBtn = document.getElementById('save-domain-blacklist-btn');
    const domainBlacklistMessage = document.getElementById('domain-blacklist-message');
    
    // Allowed Direct IPs Tab
    const allowedDirectIpsTextarea = document.getElementById('allowed-direct-ips-textarea');
    const saveAllowedDirectIpsBtn = document.getElementById('save-allowed-direct-ips-btn');
    const allowedDirectIpsMessage = document.getElementById('allowed-direct-ips-message');
    
    // Cache Settings Tab
    const cacheSizeInput = document.getElementById('cache-size');
    const maxObjectSizeValueInput = document.getElementById('max-object-size-value');
    const maxObjectSizeUnitSelect = document.getElementById('max-object-size-unit');
    const saveCacheSettingsBtn = document.getElementById('save-cache-settings-btn');
    const cacheSettingsMessage = document.getElementById('cache-settings-message');
    
    // Tab Navigation
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    // Initialize
    fetchStatus();
    fetchConfig();
    fetchSecurityFeatures();
    
    // Refresh status every 10 seconds
    setInterval(fetchStatus, 10000);
    
    // Event listeners for basic controls
    startBtn.addEventListener('click', () => controlSquid('start'));
    stopBtn.addEventListener('click', () => controlSquid('stop'));
    restartBtn.addEventListener('click', () => controlSquid('restart'));
    reloadBtn.addEventListener('click', () => controlSquid('reload'));
    updatePortBtn.addEventListener('click', updatePort);
    
    // Event listeners for security features
    saveFeaturesBtn.addEventListener('click', saveFeatureToggles);
    saveIpBlacklistBtn.addEventListener('click', saveIpBlacklist);
    saveDomainBlacklistBtn.addEventListener('click', saveDomainBlacklist);
    saveAllowedDirectIpsBtn.addEventListener('click', saveAllowedDirectIps);
    saveCacheSettingsBtn.addEventListener('click', saveCacheSettings);
    
    // Tab navigation event listeners
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            // Remove active class from all buttons
            tabButtons.forEach(btn => btn.classList.remove('active', 'border-b-2', 'border-blue-500'));
            
            // Add active class to clicked button
            button.classList.add('active', 'border-b-2', 'border-blue-500');
            
            // Show corresponding content
            const tabName = button.getAttribute('data-tab');
            
            // Hide all tab content sections
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
                content.classList.add('hidden');
            });
            
            // Show the selected tab content
            const activeTab = document.getElementById(tabName + '-tab');
            if (activeTab) {
                activeTab.classList.add('active');
                activeTab.classList.remove('hidden');
            }
            
            // Fetch data for the active tab
            if (tabName === 'ip-blacklist') {
                fetchIpBlacklist();
            } else if (tabName === 'domain-blacklist') {
                fetchDomainBlacklist();
            } else if (tabName === 'allowed-direct-ips') {
                fetchAllowedDirectIps();
            } else if (tabName === 'cache-settings') {
                fetchCacheSettings();
            }
        });
    });
    
    // Functions for basic controls (existing code)
    async function fetchStatus() {
        try {
            const response = await fetch('/api/status');
            const data = await response.json();
            
            if (data.status === 'running') {
                statusIndicator.className = 'w-4 h-4 rounded-full mr-2 status-running';
                statusText.textContent = 'Running';
            } else if (data.status === 'stopped') {
                statusIndicator.className = 'w-4 h-4 rounded-full mr-2 status-stopped';
                statusText.textContent = 'Stopped';
            } else {
                statusIndicator.className = 'w-4 h-4 rounded-full mr-2 status-error';
                statusText.textContent = 'Error';
            }
            
            statusDetails.textContent = data.details || 'No details available';
        } catch (error) {
            statusIndicator.className = 'w-4 h-4 rounded-full mr-2 status-error';
            statusText.textContent = 'Error';
            statusDetails.textContent = 'Failed to fetch status: ' + error.message;
        }
    }
    
    async function fetchConfig() {
        try {
            const response = await fetch('/api/config');
            const data = await response.json();
            
            if (data.port) {
                portInput.value = data.port;
            }
        } catch (error) {
            showConfigMessage('Failed to fetch configuration: ' + error.message, false);
        }
    }
    
    async function controlSquid(action) {
        try {
            // Disable all buttons during the operation
            setButtonsDisabled(true);
            
            // Show loading state
            statusIndicator.className = 'w-4 h-4 rounded-full mr-2 animate-pulse bg-gray-400';
            statusText.textContent = 'Processing...';
            
            const response = await fetch('/api/control', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ action })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                // Refresh status after successful action
                setTimeout(fetchStatus, 1000);
            } else {
                statusIndicator.className = 'w-4 h-4 rounded-full mr-2 status-error';
                statusText.textContent = 'Error';
                statusDetails.textContent = data.message || 'Unknown error';
            }
        } catch (error) {
            statusIndicator.className = 'w-4 h-4 rounded-full mr-2 status-error';
            statusText.textContent = 'Error';
            statusDetails.textContent = 'Failed to control Squid: ' + error.message;
        } finally {
            // Re-enable buttons
            setButtonsDisabled(false);
        }
    }
    
    async function updatePort() {
        const port = portInput.value;
        
        if (!port || !port.match(/^\d+$/) || port < 1 || port > 65535) {
            showConfigMessage('Please enter a valid port number (1-65535)', false);
            return;
        }
        
        try {
            updatePortBtn.disabled = true;
            configMessage.textContent = 'Updating...';
            configMessage.className = 'mt-2 text-sm text-gray-600';
            
            const response = await fetch('/api/config', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ port })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                showConfigMessage(data.message || 'Port updated successfully', true);
                // Refresh status after updating port
                setTimeout(fetchStatus, 1000);
            } else {
                showConfigMessage(data.message || 'Failed to update port', false);
            }
        } catch (error) {
            showConfigMessage('Failed to update port: ' + error.message, false);
        } finally {
            updatePortBtn.disabled = false;
        }
    }
    
    // Functions for security features
    async function fetchSecurityFeatures() {
        try {
            const response = await fetch('/api/security/feature-status');
            const features = await response.json();
            
            // Update toggle states
            ipBlacklistToggle.checked = features.ipBlacklist;
            domainBlacklistToggle.checked = features.domainBlacklist;
            directIpToggle.checked = features.directIpBlocking;
            userAgentToggle.checked = features.userAgentFiltering;
            malwareToggle.checked = features.malwareBlocking;
            httpsFilteringToggle.checked = features.httpsFiltering;
            
            // Also fetch the initial data for the first tab
            fetchIpBlacklist();
        } catch (error) {
            showFeaturesMessage('Failed to fetch security features: ' + error.message, false);
        }
    }
    
    async function saveFeatureToggles() {
        try {
            saveFeaturesBtn.disabled = true;
            featuresMessage.textContent = 'Saving...';
            featuresMessage.className = 'mt-2 text-sm text-gray-600';
            
            const features = {
                ipBlacklist: ipBlacklistToggle.checked,
                domainBlacklist: domainBlacklistToggle.checked,
                directIpBlocking: directIpToggle.checked,
                userAgentFiltering: userAgentToggle.checked,
                malwareBlocking: malwareToggle.checked,
                httpsFiltering: httpsFilteringToggle.checked
            };
            
            const response = await fetch('/api/security/feature-status', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(features)
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                showFeaturesMessage('Security features updated successfully', true);
                // Reload the proxy to apply changes
                setTimeout(() => controlSquid('reload'), 1000);
            } else {
                showFeaturesMessage(data.message || 'Failed to update security features', false);
            }
        } catch (error) {
            showFeaturesMessage('Failed to save security features: ' + error.message, false);
        } finally {
            saveFeaturesBtn.disabled = false;
        }
    }
    
    async function fetchIpBlacklist() {
        try {
            const response = await fetch('/api/security/blacklist-ips');
            const data = await response.json();
            
            if (data.ips) {
                ipBlacklistTextarea.value = data.ips.join('\n');
            }
        } catch (error) {
            showIpBlacklistMessage('Failed to fetch IP blacklist: ' + error.message, false);
        }
    }
    
    async function saveIpBlacklist() {
        try {
            saveIpBlacklistBtn.disabled = true;
            ipBlacklistMessage.textContent = 'Saving...';
            ipBlacklistMessage.className = 'mt-2 text-sm text-gray-600';
            
            const ips = ipBlacklistTextarea.value
                .split('\n')
                .map(line => line.trim())
                .filter(line => line !== '');
            
            const response = await fetch('/api/security/blacklist-ips', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ ips })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                showIpBlacklistMessage('IP blacklist updated successfully', true);
            } else {
                showIpBlacklistMessage(data.message || 'Failed to update IP blacklist', false);
            }
        } catch (error) {
            showIpBlacklistMessage('Failed to save IP blacklist: ' + error.message, false);
        } finally {
            saveIpBlacklistBtn.disabled = false;
        }
    }
    
    async function fetchDomainBlacklist() {
        try {
            const response = await fetch('/api/security/blacklist-domains');
            const data = await response.json();
            
            if (data.domains) {
                domainBlacklistTextarea.value = data.domains.join('\n');
            }
        } catch (error) {
            showDomainBlacklistMessage('Failed to fetch domain blacklist: ' + error.message, false);
        }
    }
    
    async function saveDomainBlacklist() {
        try {
            saveDomainBlacklistBtn.disabled = true;
            domainBlacklistMessage.textContent = 'Saving...';
            domainBlacklistMessage.className = 'mt-2 text-sm text-gray-600';
            
            const domains = domainBlacklistTextarea.value
                .split('\n')
                .map(line => line.trim())
                .filter(line => line !== '');
            
            const response = await fetch('/api/security/blacklist-domains', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ domains })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                showDomainBlacklistMessage('Domain blacklist updated successfully', true);
            } else {
                showDomainBlacklistMessage(data.message || 'Failed to update domain blacklist', false);
            }
        } catch (error) {
            showDomainBlacklistMessage('Failed to save domain blacklist: ' + error.message, false);
        } finally {
            saveDomainBlacklistBtn.disabled = false;
        }
    }
    
    async function fetchAllowedDirectIps() {
        try {
            const response = await fetch('/api/security/allowed-direct-ips');
            const data = await response.json();
            
            if (data.ips) {
                allowedDirectIpsTextarea.value = data.ips.join('\n');
            }
        } catch (error) {
            showAllowedDirectIpsMessage('Failed to fetch allowed direct IPs: ' + error.message, false);
        }
    }
    
    async function saveAllowedDirectIps() {
        try {
            saveAllowedDirectIpsBtn.disabled = true;
            allowedDirectIpsMessage.textContent = 'Saving...';
            allowedDirectIpsMessage.className = 'mt-2 text-sm text-gray-600';
            
            const ips = allowedDirectIpsTextarea.value
                .split('\n')
                .map(line => line.trim())
                .filter(line => line !== '');
            
            const response = await fetch('/api/security/allowed-direct-ips', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ ips })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                showAllowedDirectIpsMessage('Allowed direct IPs updated successfully', true);
            } else {
                showAllowedDirectIpsMessage(data.message || 'Failed to update allowed direct IPs', false);
            }
        } catch (error) {
            showAllowedDirectIpsMessage('Failed to save allowed direct IPs: ' + error.message, false);
        } finally {
            saveAllowedDirectIpsBtn.disabled = false;
        }
    }
    
    async function fetchCacheSettings() {
        try {
            const response = await fetch('/api/security/cache-settings');
            const data = await response.json();
            
            if (data.cacheSize) {
                cacheSizeInput.value = data.cacheSize;
            }
            
            if (data.maxObjectSize) {
                const [value, unit] = data.maxObjectSize.split(' ');
                maxObjectSizeValueInput.value = value;
                maxObjectSizeUnitSelect.value = unit;
            }
        } catch (error) {
            showCacheSettingsMessage('Failed to fetch cache settings: ' + error.message, false);
        }
    }
    
    async function saveCacheSettings() {
        try {
            saveCacheSettingsBtn.disabled = true;
            cacheSettingsMessage.textContent = 'Saving...';
            cacheSettingsMessage.className = 'mt-2 text-sm text-gray-600';
            
            const cacheSize = cacheSizeInput.value;
            const maxObjectSize = `${maxObjectSizeValueInput.value} ${maxObjectSizeUnitSelect.value}`;
            
            const response = await fetch('/api/security/cache-settings', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ cacheSize, maxObjectSize })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                showCacheSettingsMessage('Cache settings updated successfully', true);
            } else {
                showCacheSettingsMessage(data.message || 'Failed to update cache settings', false);
            }
        } catch (error) {
            showCacheSettingsMessage('Failed to save cache settings: ' + error.message, false);
        } finally {
            saveCacheSettingsBtn.disabled = false;
        }
    }
    
    // Helper functions for UI messages
    function showConfigMessage(message, isSuccess) {
        configMessage.textContent = message;
        configMessage.className = isSuccess 
            ? 'mt-2 text-sm message-success' 
            : 'mt-2 text-sm message-error';
        
        // Clear message after 5 seconds
        setTimeout(() => {
            configMessage.textContent = '';
        }, 5000);
    }
    
    function showFeaturesMessage(message, isSuccess) {
        featuresMessage.textContent = message;
        featuresMessage.className = isSuccess 
            ? 'mt-2 text-sm message-success' 
            : 'mt-2 text-sm message-error';
        
        // Clear message after 5 seconds
        setTimeout(() => {
            featuresMessage.textContent = '';
        }, 5000);
    }
    
    function showIpBlacklistMessage(message, isSuccess) {
        ipBlacklistMessage.textContent = message;
        ipBlacklistMessage.className = isSuccess 
            ? 'mt-2 text-sm message-success' 
            : 'mt-2 text-sm message-error';
        
        // Clear message after 5 seconds
        setTimeout(() => {
            ipBlacklistMessage.textContent = '';
        }, 5000);
    }
    
    function showDomainBlacklistMessage(message, isSuccess) {
        domainBlacklistMessage.textContent = message;
        domainBlacklistMessage.className = isSuccess 
            ? 'mt-2 text-sm message-success' 
            : 'mt-2 text-sm message-error';
        
        // Clear message after 5 seconds
        setTimeout(() => {
            domainBlacklistMessage.textContent = '';
        }, 5000);
    }
    
    function showAllowedDirectIpsMessage(message, isSuccess) {
        allowedDirectIpsMessage.textContent = message;
        allowedDirectIpsMessage.className = isSuccess 
            ? 'mt-2 text-sm message-success' 
            : 'mt-2 text-sm message-error';
        
        // Clear message after 5 seconds
        setTimeout(() => {
            allowedDirectIpsMessage.textContent = '';
        }, 5000);
    }
    
    function showCacheSettingsMessage(message, isSuccess) {
        cacheSettingsMessage.textContent = message;
        cacheSettingsMessage.className = isSuccess 
            ? 'mt-2 text-sm message-success' 
            : 'mt-2 text-sm message-error';
        
        // Clear message after 5 seconds
        setTimeout(() => {
            cacheSettingsMessage.textContent = '';
        }, 5000);
    }
    
    function setButtonsDisabled(disabled) {
        startBtn.disabled = disabled;
        stopBtn.disabled = disabled;
        restartBtn.disabled = disabled;
        reloadBtn.disabled = disabled;
    }
});