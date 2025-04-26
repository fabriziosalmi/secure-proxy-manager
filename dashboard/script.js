// Squid Proxy Dashboard JavaScript

/**
 * Toast Notification System
 */
class ToastNotification {
    constructor() {
        this.container = null;
        this.initialize();
    }
    
    initialize() {
        // Create container if it doesn't exist
        if (!this.container) {
            this.container = document.createElement('div');
            this.container.className = 'toast-container';
            document.body.appendChild(this.container);
        }
    }
    
    show(options) {
        const {
            title = '',
            message = '',
            type = 'info', // info, success, error, warning
            duration = 3000
        } = options;
        
        // Create toast element
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        
        // Set icon based on type
        let icon = 'ri-information-line';
        if (type === 'success') icon = 'ri-checkbox-circle-line';
        if (type === 'error') icon = 'ri-error-warning-line';
        if (type === 'warning') icon = 'ri-alert-line';
        
        toast.innerHTML = `
            <div class="toast-icon"><i class="${icon}"></i></div>
            <div class="toast-content">
                ${title ? `<div class="toast-title">${title}</div>` : ''}
                <div class="toast-message">${message}</div>
            </div>
            <button class="toast-close" aria-label="Close notification">
                <i class="ri-close-line"></i>
            </button>
        `;
        
        // Add to container
        this.container.appendChild(toast);
        
        // Add close button event listener
        const closeBtn = toast.querySelector('.toast-close');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                this.close(toast);
            });
        }
        
        // Auto close after duration
        if (duration > 0) {
            setTimeout(() => {
                this.close(toast);
            }, duration);
        }
        
        return toast;
    }
    
    close(toast) {
        toast.classList.add('closing');
        
        // Remove after animation completes
        toast.addEventListener('animationend', () => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        });
    }
    
    success(message, title = 'Success') {
        return this.show({ title, message, type: 'success' });
    }
    
    error(message, title = 'Error') {
        return this.show({ title, message, type: 'error', duration: 5000 });
    }
    
    info(message, title = 'Information') {
        return this.show({ title, message, type: 'info' });
    }
    
    warning(message, title = 'Warning') {
        return this.show({ title, message, type: 'warning', duration: 4000 });
    }
}

// Create a global toast instance
const toast = new ToastNotification();

/**
 * Enhanced Security Feature - API Request with CSRF protection and improved error handling
 */
async function apiRequest(url, options = {}) {
    try {
        // Add CSRF token to headers
        if (!options.headers) options.headers = {};
        
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
        if (csrfToken) {
            options.headers['X-CSRF-Token'] = csrfToken;
        }
        
        // Set default content type for POST/PUT requests
        if ((options.method === 'POST' || options.method === 'PUT') && 
            !options.headers['Content-Type'] && 
            !(options.body instanceof FormData)) {
            options.headers['Content-Type'] = 'application/json';
        }
        
        // Add credentials for all requests
        options.credentials = 'same-origin';
        
        // Perform request with timeout to prevent hanging requests
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout
        
        const response = await fetch(url, {
            ...options,
            signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        // Handle HTTP errors
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({
                message: `HTTP error ${response.status}: ${response.statusText}`
            }));
            
            throw new Error(errorData.message || `HTTP error ${response.status}: ${response.statusText}`);
        }
        
        // Parse JSON if the response has content
        if (response.status !== 204) { // 204 No Content
            return await response.json();
        }
        
        return { status: 'success' };
    } catch (error) {
        // Handle request cancellation
        if (error.name === 'AbortError') {
            console.error('Request timeout:', url);
            throw new Error('Request timed out. Please try again.');
        }
        
        console.error(`Error in API request to ${url}:`, error);
        throw error;
    }
}

/**
 * Enhanced User Experience - Update the toast notifications when showing messages
 */
function enhancedShowMessage(element, message, isSuccess) {
    // Still update the DOM element if provided (backward compatibility)
    if (element) {
        element.textContent = message;
        element.className = 'message';
        
        if (isSuccess === true) {
            element.classList.add('message-success');
        } else if (isSuccess === false) {
            element.classList.add('message-error');
        } else {
            element.classList.add('message-info');
        }
        
        // Clear message after 5 seconds
        setTimeout(() => {
            element.textContent = '';
            element.className = '';
        }, 5000);
    }
    
    // Also show a toast notification for better UX
    if (isSuccess === true) {
        toast.success(message);
    } else if (isSuccess === false) {
        toast.error(message);
    } else {
        toast.info(message);
    }
    
    // Log errors to console for debugging
    if (isSuccess === false) {
        console.error('Error:', message);
    }
}

// Replace the original showMessage function with this enhanced version
function showMessage(element, message, isSuccess) {
    return enhancedShowMessage(element, message, isSuccess);
}

// Avoid using regular console.error directly - instead use this function that can be extended later
function logError(message, error) {
    console.error(message, error);
    // In the future, this could send errors to a monitoring service
}

/**
 * Enhanced data validation
 */ 
const validationRules = {
    port: {
        validate: value => value && /^\d+$/.test(value) && parseInt(value) >= 1 && parseInt(value) <= 65535,
        message: 'Please enter a valid port number (1-65535)'
    },
    ip: {
        validate: value => /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(value) || 
                           /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(value) ||
                           value.startsWith('#'),
        message: 'Please enter a valid IP address (IPv4 or IPv6)'
    },
    domain: {
        validate: value => /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(value) ||
                           value.startsWith('#'),
        message: 'Please enter a valid domain name'
    },
    number: {
        validate: value => value && /^\d+$/.test(value),
        message: 'Please enter a valid number'
    },
    cacheSize: {
        validate: value => value && /^\d+$/.test(value) && parseInt(value) >= 10 && parseInt(value) <= 10000,
        message: 'Cache size must be between 10 and 10000 MB'
    },
    required: {
        validate: value => value && value.trim() !== '',
        message: 'This field is required'
    }
};

function validateField(value, type) {
    const rule = validationRules[type];
    if (!rule) return { isValid: true, message: '' };
    
    const isValid = rule.validate(value);
    return { isValid, message: isValid ? '' : rule.message };
}

document.addEventListener('DOMContentLoaded', function() {
    // Path detection to determine which page we're on
    const currentPath = window.location.pathname;
    const pageName = currentPath.split('/').pop() || 'index.html';
    
    // Elements - Main Controls (shared across pages)
    const headerStatusIndicator = document.getElementById('header-status-indicator');
    const headerStatusText = document.getElementById('header-status-text');
    const headerClientsCount = document.getElementById('header-clients-count');
    const currentTimeEl = document.getElementById('current-time');
    const themeToggleBtn = document.getElementById('theme-toggle');
    const themeToggleLightIcon = document.getElementById('theme-toggle-light-icon');
    const themeToggleDarkIcon = document.getElementById('theme-toggle-dark-icon');
    
    // Initialize time and header elements for all pages
    updateCurrentTime();
    fetchStatus(true); // Only update header
    fetchClientsCount();
    initThemeToggle();
    
    // Update current time every minute
    setInterval(updateCurrentTime, 60000);
    
    // Refresh header stats every 15 seconds
    setInterval(() => { 
        fetchStatus(true); 
        fetchClientsCount(); 
    }, 15000);
    
    // Main Dashboard Page (index.html)
    if (pageName === 'index.html' || pageName === '') {
        initDashboardPage();
    }
    // Settings Page
    else if (pageName === 'settings.html') {
        initSettingsPage();
    } 
    // Logs Page
    else if (pageName === 'logs.html') {
        initLogsPage();
    }
    
    // Theme toggle initialization
    function initThemeToggle() {
        if (!themeToggleBtn) return;
        
        // Get current theme from localStorage or system preference
        const savedTheme = localStorage.getItem('theme') || 'system';
        setTheme(savedTheme);
        
        // Add event listener for theme toggle
        themeToggleBtn.addEventListener('click', () => {
            // Get current theme
            const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
            
            // Toggle between light and dark
            const newTheme = currentTheme === 'light' ? 'dark' : 'light';
            setTheme(newTheme);
            localStorage.setItem('theme', newTheme);
        });
    }
    
    // Set theme on document and update UI
    function setTheme(themeName) {
        document.documentElement.setAttribute('data-theme', themeName);
        
        // Update icon visibility
        if (themeToggleLightIcon && themeToggleDarkIcon) {
            // For light theme or system theme with light preference
            if (themeName === 'light' || 
                (themeName === 'system' && !window.matchMedia('(prefers-color-scheme: dark)').matches)) {
                themeToggleLightIcon.classList.remove('hidden');
                themeToggleDarkIcon.classList.add('hidden');
            } else {
                // For dark theme or system theme with dark preference
                themeToggleLightIcon.classList.add('hidden');
                themeToggleDarkIcon.classList.remove('hidden');
            }
        }
        
        // Update buttons in settings page if they exist
        document.querySelectorAll('.theme-btn').forEach(btn => {
            if (btn.dataset.theme === themeName) {
                btn.classList.add('active');
            } else {
                btn.classList.remove('active');
            }
        });
    }
    
    // Listen for system color scheme changes
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
        if (localStorage.getItem('theme') === 'system') {
            setTheme('system');
        }
    });
    
    // Functions for UI elements (shared across pages)
    function updateCurrentTime() {
        if (currentTimeEl) {
            const now = new Date();
            const options = { 
                weekday: 'long', 
                year: 'numeric', 
                month: 'short', 
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            };
            currentTimeEl.textContent = now.toLocaleDateString('en-US', options);
        }
    }
    
    // Function to fetch status - can optionally update only the header
    async function fetchStatus(headerOnly = false) {
        try {
            // If we have a refresh button and not in header-only mode, show loading state
            const refreshStatusBtn = document.getElementById('refresh-status-btn');
            if (refreshStatusBtn && !headerOnly) {
                refreshStatusBtn.classList.add('animate-spin');
            }
            
            const response = await safeFetch('/api/status');
            const data = await response.json();
            
            // Always update the header
            if (headerStatusText && headerStatusIndicator) {
                headerStatusText.textContent = data.status === 'running' ? 'Running' : data.status === 'stopped' ? 'Stopped' : 'Error';
                
                headerStatusIndicator.classList.remove('header-status-running', 'header-status-stopped', 'header-status-error');
                if (data.status === 'running') {
                    headerStatusIndicator.classList.add('header-status-running');
                } else if (data.status === 'stopped') {
                    headerStatusIndicator.classList.add('header-status-stopped');
                } else {
                    headerStatusIndicator.classList.add('header-status-error');
                }
            }
            
            // Update the main status elements if we're not in header-only mode
            if (!headerOnly) {
                const statusIndicator = document.getElementById('status-indicator');
                const statusText = document.getElementById('status-text');
                const statusDetails = document.getElementById('status-details');
                
                if (statusIndicator && statusText) {
                    statusIndicator.className = 'status-indicator';
                    if (data.status === 'running') {
                        statusIndicator.classList.add('status-running');
                        statusText.textContent = 'Running';
                        statusText.className = 'text-lg font-medium text-success';
                    } else if (data.status === 'stopped') {
                        statusIndicator.classList.add('status-stopped');
                        statusText.textContent = 'Stopped';
                        statusText.className = 'text-lg font-medium text-danger';
                    } else {
                        statusIndicator.classList.add('status-error');
                        statusText.textContent = 'Error';
                        statusText.className = 'text-lg font-medium text-warning';
                    }
                }
                
                if (statusDetails) {
                    statusDetails.textContent = data.details || 'No details available';
                }
            }
        } catch (error) {
            console.error('Error fetching status:', error);
            if (headerStatusText && headerStatusIndicator) {
                headerStatusText.textContent = 'Error';
                headerStatusIndicator.classList.remove('header-status-running', 'header-status-stopped');
                headerStatusIndicator.classList.add('header-status-error');
            }
            
            // Update main status if not in header-only mode
            if (!headerOnly) {
                const statusIndicator = document.getElementById('status-indicator');
                const statusText = document.getElementById('status-text');
                const statusDetails = document.getElementById('status-details');
                
                if (statusIndicator && statusText) {
                    statusIndicator.className = 'status-indicator status-error';
                    statusText.textContent = 'Error';
                    statusText.className = 'text-lg font-medium text-warning';
                }
                
                if (statusDetails) {
                    statusDetails.textContent = 'Failed to fetch status: ' + error.message;
                }
            }
        } finally {
            // If we have a refresh button and not in header-only mode, remove loading state
            const refreshStatusBtn = document.getElementById('refresh-status-btn');
            if (refreshStatusBtn && !headerOnly) {
                refreshStatusBtn.classList.remove('animate-spin');
            }
        }
    }
    
    // Fetch client count (shared)
    async function fetchClientsCount() {
        if (headerClientsCount) {
            try {
                // replace with real endpoint when available
                const response = await safeFetch('/api/clients/count');
                const result = await response.json();
                headerClientsCount.textContent = result.count || '0';
            } catch {
                headerClientsCount.textContent = '0';
            }
        }
    }
    
    // Control squid (used on multiple pages)
    async function controlSquid(action) {
        try {
            // Disable all buttons during the operation if they exist
            const startBtn = document.getElementById('start-btn');
            const stopBtn = document.getElementById('stop-btn');
            const restartBtn = document.getElementById('restart-btn');
            const reloadBtn = document.getElementById('reload-btn');
            
            const buttons = [startBtn, stopBtn, restartBtn, reloadBtn].filter(btn => btn !== null);
            buttons.forEach(btn => { if (btn) btn.disabled = true; });
            
            // Show loading state if status elements exist
            const statusIndicator = document.getElementById('status-indicator');
            const statusText = document.getElementById('status-text');
            
            if (statusIndicator && statusText) {
                statusIndicator.className = 'status-indicator';
                statusIndicator.classList.add('animate-pulse', 'bg-gray-400');
                statusText.textContent = 'Processing...';
                statusText.className = 'text-lg font-medium text-gray-600';
            }
            
            const response = await safeFetch('/api/control', {
                method: 'POST',
                headers: addCSRFToken({
                    'Content-Type': 'application/json'
                }),
                body: JSON.stringify({ action })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                // Refresh status after successful action
                setTimeout(() => fetchStatus(false), 1000);
            } else {
                if (statusIndicator && statusText) {
                    statusIndicator.className = 'status-indicator status-error';
                    statusText.textContent = 'Error';
                    statusText.className = 'text-lg font-medium text-warning';
                }
                
                const statusDetails = document.getElementById('status-details');
                if (statusDetails) {
                    statusDetails.textContent = data.message || 'Unknown error';
                } else {
                    alert('Error: ' + (data.message || 'Unknown error'));
                }
            }
        } catch (error) {
            const statusIndicator = document.getElementById('status-indicator');
            const statusText = document.getElementById('status-text');
            const statusDetails = document.getElementById('status-details');
            
            if (statusIndicator && statusText) {
                statusIndicator.className = 'status-indicator status-error';
                statusText.textContent = 'Error';
                statusText.className = 'text-lg font-medium text-warning';
            }
            
            if (statusDetails) {
                statusDetails.textContent = 'Failed to control Squid: ' + error.message;
            } else {
                alert('Failed to control Squid: ' + error.message);
            }
        } finally {
            // Re-enable buttons
            const startBtn = document.getElementById('start-btn');
            const stopBtn = document.getElementById('stop-btn');
            const restartBtn = document.getElementById('restart-btn');
            const reloadBtn = document.getElementById('reload-btn');
            
            const buttons = [startBtn, stopBtn, restartBtn, reloadBtn].filter(btn => btn !== null);
            buttons.forEach(btn => { if (btn) btn.disabled = false; });
        }
    }
    
    // Helper function to show messages (used on multiple pages)
    function showMessage(element, message, isSuccess) {
        if (!element) return;
        
        element.textContent = message;
        element.className = 'message';
        
        if (isSuccess === true) {
            element.classList.add('message-success');
        } else if (isSuccess === false) {
            element.classList.add('message-error');
        } else {
            element.classList.add('message-info');
        }
        
        // Clear message after 5 seconds
        setTimeout(() => {
            element.textContent = '';
            element.className = '';
        }, 5000);
        
        // Log errors to console for debugging
        if (isSuccess === false) {
            console.error('Error:', message);
        }
    }
    
    // Global error handler for fetch operations
    async function safeFetch(url, options = {}) {
        try {
            const response = await fetch(url, options);
            if (!response.ok) {
                throw new Error(`HTTP error ${response.status}: ${response.statusText}`);
            }
            return response;
        } catch (error) {
            console.error(`Error fetching ${url}:`, error);
            throw error;
        }
    }
    
    // Helper function for debouncing rapidly triggered events
    function debounce(func, wait = 300) {
        let timeout;
        return function(...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), wait);
        };
    }

    // Input validation helper 
    function validateInput(input, type) {
        switch(type) {
            case 'port':
                return input && /^\d+$/.test(input) && parseInt(input) >= 1 && parseInt(input) <= 65535;
            case 'ip':
                // Basic IP validation, more complex patterns could be added
                return /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(input) || 
                       /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(input);
            case 'domain':
                return /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(input);
            case 'number':
                return input && /^\d+$/.test(input);
            default:
                return true;
        }
    }

    // Add local storage for persisting user preferences
    function saveUserPreference(key, value) {
        try {
            // Get existing preferences or create new object
            const preferences = JSON.parse(localStorage.getItem('proxyPreferences') || '{}');
            preferences[key] = value;
            localStorage.setItem('proxyPreferences', JSON.stringify(preferences));
            return true;
        } catch (error) {
            console.error('Failed to save preference:', error);
            return false;
        }
    }

    function getUserPreference(key, defaultValue = null) {
        try {
            const preferences = JSON.parse(localStorage.getItem('proxyPreferences') || '{}');
            return preferences[key] !== undefined ? preferences[key] : defaultValue;
        } catch (error) {
            console.error('Failed to get preference:', error);
            return defaultValue;
        }
    }

    // Add CSRF protection helper
    function addCSRFToken(headers = {}) {
        // This assumes your backend provides a CSRF token in a meta tag
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
        if (csrfToken) {
            return { ...headers, 'X-CSRF-Token': csrfToken };
        }
        return headers;
    }

    // Initialize Dashboard Page
    function initDashboardPage() {
        // Elements - Main Controls
        const statusIndicator = document.getElementById('status-indicator');
        const statusText = document.getElementById('status-text');
        const statusDetails = document.getElementById('status-details');
        const startBtn = document.getElementById('start-btn');
        const stopBtn = document.getElementById('stop-btn');
        const restartBtn = document.getElementById('restart-btn');
        const reloadBtn = document.getElementById('reload-btn');
        const refreshStatusBtn = document.getElementById('refresh-status-btn');
        
        // Real-time Monitoring Elements
        const connectionsCount = document.getElementById('connections-count');
        const connectionsBar = document.getElementById('connections-bar');
        const connectionsLimit = document.getElementById('connections-limit');
        const clientsCount = document.getElementById('clients-count');
        const clientsBar = document.getElementById('clients-bar');
        const clientsLimit = document.getElementById('clients-limit');
        const peakConnections = document.getElementById('peak-connections');
        const peakClients = document.getElementById('peak-clients');
        const lastUpdateTime = document.getElementById('last-update-time');
        const toggleAutoRefresh = document.getElementById('toggle-auto-refresh');
        const autoRefreshStatus = document.getElementById('auto-refresh-status');
        const refreshConnectionsBtn = document.getElementById('refresh-connections-btn');
        
        // State variables for real-time monitoring
        let connectionsAutoRefresh = false;
        let connectionsRefreshInterval = null;
        let peakConnectionsValue = 0;
        let peakClientsValue = 0;
        
        // Initialize
        fetchStatus();
        fetchRealTimeStats();
        
        // Event listeners for basic controls
        if (startBtn) startBtn.addEventListener('click', () => controlSquid('start'));
        if (stopBtn) stopBtn.addEventListener('click', () => controlSquid('stop'));
        if (restartBtn) restartBtn.addEventListener('click', () => controlSquid('restart'));
        if (reloadBtn) reloadBtn.addEventListener('click', () => controlSquid('reload'));
        if (refreshStatusBtn) refreshStatusBtn.addEventListener('click', () => fetchStatus());
        
        // Event listeners for real-time monitoring
        if (refreshConnectionsBtn) refreshConnectionsBtn.addEventListener('click', fetchRealTimeStats);
        if (toggleAutoRefresh) toggleAutoRefresh.addEventListener('click', toggleConnectionsAutoRefresh);
        
        // Functions for real-time monitoring
        function toggleConnectionsAutoRefresh() {
            connectionsAutoRefresh = !connectionsAutoRefresh;
            
            if (autoRefreshStatus) {
                autoRefreshStatus.textContent = connectionsAutoRefresh ? 'On' : 'Off';
            }
            
            if (connectionsAutoRefresh) {
                // Start auto-refresh (every 5 seconds)
                connectionsRefreshInterval = setInterval(fetchRealTimeStats, 5000);
            } else {
                // Stop auto-refresh
                if (connectionsRefreshInterval) {
                    clearInterval(connectionsRefreshInterval);
                    connectionsRefreshInterval = null;
                }
            }
        }
        
        async function fetchRealTimeStats() {
            if (!connectionsCount || !clientsCount) return;
            
            try {
                if (refreshConnectionsBtn) refreshConnectionsBtn.classList.add('animate-spin');
                
                const response = await safeFetch('/api/stats/realtime');
                const data = await response.json();
                
                // Update connections count
                const connections = data.connections || 0;
                const maxConnections = data.maxConnections || 1000;
                const connectionPercentage = Math.min(100, Math.round((connections / maxConnections) * 100));
                
                if (connectionsCount) connectionsCount.textContent = connections;
                if (connectionsBar) connectionsBar.style.width = `${connectionPercentage}%`;
                if (connectionsLimit) connectionsLimit.textContent = maxConnections;
                
                // Update clients count
                const clients = data.clients || 0;
                const maxClients = data.maxClients || 100;
                const clientPercentage = Math.min(100, Math.round((clients / maxClients) * 100));
                
                if (clientsCount) clientsCount.textContent = clients;
                if (clientsBar) clientsBar.style.width = `${clientPercentage}%`;
                if (clientsLimit) clientsLimit.textContent = maxClients;
                
                // Update peak values
                peakConnectionsValue = Math.max(peakConnectionsValue, connections);
                peakClientsValue = Math.max(peakClientsValue, clients);
                
                if (peakConnections) peakConnections.textContent = peakConnectionsValue;
                if (peakClients) peakClients.textContent = peakClientsValue;
                
                // Update last updated time
                if (lastUpdateTime) {
                    const now = new Date();
                    lastUpdateTime.textContent = now.toLocaleTimeString();
                }
                
                // Handle color changes based on usage
                updateBarColors(connectionsBar, connectionPercentage);
                updateBarColors(clientsBar, clientPercentage);
                
            } catch (error) {
                console.error('Error fetching real-time stats:', error);
                
                // Show error state
                if (connectionsCount) connectionsCount.textContent = 'Error';
                if (clientsCount) clientsCount.textContent = 'Error';
                
            } finally {
                if (refreshConnectionsBtn) refreshConnectionsBtn.classList.remove('animate-spin');
            }
        }
        
        function updateBarColors(barElement, percentage) {
            if (!barElement) return;
            
            // Remove existing color classes
            barElement.classList.remove('bg-primary', 'bg-warning', 'bg-danger');
            
            // Add appropriate color class based on usage percentage
            if (percentage < 70) {
                barElement.classList.add('bg-primary');
            } else if (percentage < 90) {
                barElement.classList.add('bg-warning');
            } else {
                barElement.classList.add('bg-danger');
            }
        }
        
        // Log Controls
        const downloadLogsBtn = document.getElementById('download-logs-btn');
        const clearLogsBtn = document.getElementById('clear-logs-btn');
        
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
        
        // Tab Navigation
        const tabButtons = document.querySelectorAll('.tab-btn');
        const tabContents = document.querySelectorAll('.tab-content');
        
        // Initialize
        fetchStatus();
        fetchConfig();
        fetchSecurityFeatures();
        
        // Event listeners for basic controls
        if (startBtn) startBtn.addEventListener('click', () => controlSquid('start'));
        if (stopBtn) stopBtn.addEventListener('click', () => controlSquid('stop'));
        if (restartBtn) restartBtn.addEventListener('click', () => controlSquid('restart'));
        if (reloadBtn) reloadBtn.addEventListener('click', () => controlSquid('reload'));
        if (refreshStatusBtn) refreshStatusBtn.addEventListener('click', () => fetchStatus());
        
        // Log control event listeners
        if (downloadLogsBtn) downloadLogsBtn.addEventListener('click', downloadLogs);
        if (clearLogsBtn) clearLogsBtn.addEventListener('click', clearLogs);
        
        // Event listeners for security features
        if (saveFeaturesBtn) saveFeaturesBtn.addEventListener('click', saveFeatureToggles);
        if (saveIpBlacklistBtn) saveIpBlacklistBtn.addEventListener('click', saveIpBlacklist);
        if (saveDomainBlacklistBtn) saveDomainBlacklistBtn.addEventListener('click', saveDomainBlacklist);
        if (saveAllowedDirectIpsBtn) saveAllowedDirectIpsBtn.addEventListener('click', saveAllowedDirectIps);
        
        // Tab navigation event listeners
        if (tabButtons) {
            tabButtons.forEach(button => {
                button.addEventListener('click', () => {
                    // Remove active class from all buttons
                    tabButtons.forEach(btn => btn.classList.remove('active'));
                    
                    // Add active class to clicked button
                    button.classList.add('active');
                    
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
                    }
                });
            });
        }
        
        // Functions for basic controls
        async function fetchConfig() {
            try {
                const response = await safeFetch('/api/config');
                const data = await response.json();
                
                if (data.port && portInput) {
                    portInput.value = data.port;
                }
                
                // Load cache settings if available
                if (data.cacheSize && cacheSizeInput) {
                    cacheSizeInput.value = data.cacheSize;
                }
                
                if (data.maxObjectSize && maxObjectSizeValueInput && maxObjectSizeUnitSelect) {
                    const [value, unit] = data.maxObjectSize.split(' ');
                    maxObjectSizeValueInput.value = value;
                    if (unit) {
                        maxObjectSizeUnitSelect.value = unit;
                    }
                }
            } catch (error) {
                if (configMessage) {
                    showMessage(configMessage, 'Failed to fetch configuration: ' + error.message, false);
                }
            }
        }
        
        async function updatePort() {
            if (!portInput) return;
            const port = portInput.value;
            
            if (!validateInput(port, 'port')) {
                showMessage(configMessage, 'Please enter a valid port number (1-65535)', false);
                return;
            }
            
            try {
                if (updatePortBtn) updatePortBtn.disabled = true;
                showMessage(configMessage, 'Updating...', null);
                
                const response = await safeFetch('/api/config', {
                    method: 'POST',
                    headers: addCSRFToken({
                        'Content-Type': 'application/json'
                    }),
                    body: JSON.stringify({ port })
                });
                
                const data = await response.json();
                
                if (data.status === 'success') {
                    showMessage(configMessage, data.message || 'Port updated successfully', true);
                    // Refresh status after updating port
                    setTimeout(fetchStatus, 1000);
                } else {
                    showMessage(configMessage, data.message || 'Failed to update port', false);
                }
            } catch (error) {
                showMessage(configMessage, 'Failed to update port: ' + error.message, false);
            } finally {
                if (updatePortBtn) updatePortBtn.disabled = false;
            }
        }
        
        // Functions for log management
        async function downloadLogs() {
            try {
                if (downloadLogsBtn) downloadLogsBtn.classList.add('animate-spin');
                
                const response = await safeFetch('/api/logs/download');
                const blob = await response.blob();
                
                // Create download link
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = url;
                a.download = 'squid-logs.txt';
                document.body.appendChild(a);
                a.click();
                
                // Clean up
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
            } catch (error) {
                alert('Failed to download logs: ' + error.message);
            } finally {
                if (downloadLogsBtn) downloadLogsBtn.classList.remove('animate-spin');
            }
        }
        
        async function clearLogs() {
            if (!confirm('Are you sure you want to clear the logs? This action cannot be undone.')) {
                return;
            }
            
            try {
                if (clearLogsBtn) clearLogsBtn.classList.add('animate-spin');
                
                const response = await safeFetch('/api/logs/clear', {
                    method: 'POST',
                    headers: addCSRFToken()
                });
                
                const data = await response.json();
                
                if (data.status === 'success') {
                    if (statusDetails) statusDetails.textContent = '';
                    fetchStatus();
                } else {
                    alert('Failed to clear logs: ' + (data.message || 'Unknown error'));
                }
            } catch (error) {
                alert('Failed to clear logs: ' + error.message);
            } finally {
                if (clearLogsBtn) clearLogsBtn.classList.remove('animate-spin');
            }
        }
        
        // Functions for security features
        async function fetchSecurityFeatures() {
            try {
                const response = await safeFetch('/api/security/feature-status');
                const features = await response.json();
                
                // Update toggle states
                if (ipBlacklistToggle) ipBlacklistToggle.checked = features.ipBlacklist;
                if (domainBlacklistToggle) domainBlacklistToggle.checked = features.domainBlacklist;
                if (directIpToggle) directIpToggle.checked = features.directIpBlocking;
                if (userAgentToggle) userAgentToggle.checked = features.userAgentFiltering;
                if (malwareToggle) malwareToggle.checked = features.malwareBlocking;
                if (httpsFilteringToggle) httpsFilteringToggle.checked = features.httpsFiltering === true ? true : false;
                
                // Also fetch the initial data for the first tab
                fetchIpBlacklist();
            } catch (error) {
                if (featuresMessage) {
                    showMessage(featuresMessage, 'Failed to fetch security features: ' + error.message, false);
                }
            }
        }
        
        async function saveFeatureToggles() {
            if (!ipBlacklistToggle) return;
            
            try {
                if (saveFeaturesBtn) saveFeaturesBtn.disabled = true;
                if (featuresMessage) showMessage(featuresMessage, 'Saving...', null);
                
                const features = {
                    ipBlacklist: ipBlacklistToggle.checked,
                    domainBlacklist: domainBlacklistToggle.checked,
                    directIpBlocking: directIpToggle.checked,
                    userAgentFiltering: userAgentToggle.checked,
                    malwareBlocking: malwareToggle.checked,
                    httpsFiltering: httpsFilteringToggle.checked
                };
                
                const response = await safeFetch('/api/security/feature-status', {
                    method: 'POST',
                    headers: addCSRFToken({
                        'Content-Type': 'application/json'
                    }),
                    body: JSON.stringify(features)
                });
                
                const data = await response.json();
                
                if (data.status === 'success') {
                    showMessage(featuresMessage, 'Security features updated successfully', true);
                    // Reload the proxy to apply changes
                    setTimeout(() => controlSquid('reload'), 1000);
                } else {
                    showMessage(featuresMessage, data.message || 'Failed to update security features', false);
                }
            } catch (error) {
                if (featuresMessage) {
                    showMessage(featuresMessage, 'Failed to save security features: ' + error.message, false);
                }
            } finally {
                if (saveFeaturesBtn) saveFeaturesBtn.disabled = false;
            }
        }
        
        async function fetchIpBlacklist() {
            if (!ipBlacklistTextarea) return;
            
            try {
                ipBlacklistTextarea.disabled = true;
                ipBlacklistTextarea.placeholder = 'Loading...';
                
                const response = await safeFetch('/api/security/blacklist-ips');
                const data = await response.json();
                
                if (data.ips) {
                    ipBlacklistTextarea.value = data.ips.join('\n');
                } else {
                    ipBlacklistTextarea.value = '';
                }
            } catch (error) {
                if (ipBlacklistMessage) {
                    showMessage(ipBlacklistMessage, 'Failed to fetch IP blacklist: ' + error.message, false);
                }
            } finally {
                ipBlacklistTextarea.disabled = false;
                ipBlacklistTextarea.placeholder = 'Enter IPs to blacklist, one per line\nExample:\n192.168.1.100\n10.0.0.5';
            }
        }
        
        async function saveIpBlacklist() {
            if (!ipBlacklistTextarea) return;
            
            try {
                if (saveIpBlacklistBtn) saveIpBlacklistBtn.disabled = true;
                if (ipBlacklistMessage) showMessage(ipBlacklistMessage, 'Saving...', null);
                
                const ips = ipBlacklistTextarea.value
                    .split('\n')
                    .map(line => line.trim())
                    .filter(line => validateInput(line, 'ip'));
                
                const response = await safeFetch('/api/security/blacklist-ips', {
                    method: 'POST',
                    headers: addCSRFToken({
                        'Content-Type': 'application/json'
                    }),
                    body: JSON.stringify({ ips })
                });
                
                const data = await response.json();
                
                if (data.status === 'success') {
                    showMessage(ipBlacklistMessage, 'IP blacklist updated successfully', true);
                } else {
                    showMessage(ipBlacklistMessage, data.message || 'Failed to update IP blacklist', false);
                }
            } catch (error) {
                if (ipBlacklistMessage) {
                    showMessage(ipBlacklistMessage, 'Failed to save IP blacklist: ' + error.message, false);
                }
            } finally {
                if (saveIpBlacklistBtn) saveIpBlacklistBtn.disabled = false;
            }
        }
        
        async function fetchDomainBlacklist() {
            if (!domainBlacklistTextarea) return;
            
            try {
                domainBlacklistTextarea.disabled = true;
                domainBlacklistTextarea.placeholder = 'Loading...';
                
                const response = await safeFetch('/api/security/blacklist-domains');
                const data = await response.json();
                
                if (data.domains) {
                    domainBlacklistTextarea.value = data.domains.join('\n');
                } else {
                    domainBlacklistTextarea.value = '';
                }
            } catch (error) {
                if (domainBlacklistMessage) {
                    showMessage(domainBlacklistMessage, 'Failed to fetch domain blacklist: ' + error.message, false);
                }
            } finally {
                domainBlacklistTextarea.disabled = false;
                domainBlacklistTextarea.placeholder = 'Enter domains to blacklist, one per line\nExample:\nexample.com\nads.example.org';
            }
        }
        
        async function saveDomainBlacklist() {
            if (!domainBlacklistTextarea) return;
            
            try {
                if (saveDomainBlacklistBtn) saveDomainBlacklistBtn.disabled = true;
                if (domainBlacklistMessage) showMessage(domainBlacklistMessage, 'Saving...', null);
                
                const domains = domainBlacklistTextarea.value
                    .split('\n')
                    .map(line => line.trim())
                    .filter(line => validateInput(line, 'domain'));
                
                const response = await safeFetch('/api/security/blacklist-domains', {
                    method: 'POST',
                    headers: addCSRFToken({
                        'Content-Type': 'application/json'
                    }),
                    body: JSON.stringify({ domains })
                });
                
                const data = await response.json();
                
                if (data.status === 'success') {
                    showMessage(domainBlacklistMessage, 'Domain blacklist updated successfully', true);
                } else {
                    showMessage(domainBlacklistMessage, data.message || 'Failed to update domain blacklist', false);
                }
            } catch (error) {
                if (domainBlacklistMessage) {
                    showMessage(domainBlacklistMessage, 'Failed to save domain blacklist: ' + error.message, false);
                }
            } finally {
                if (saveDomainBlacklistBtn) saveDomainBlacklistBtn.disabled = false;
            }
        }
        
        async function fetchAllowedDirectIps() {
            if (!allowedDirectIpsTextarea) return;
            
            try {
                allowedDirectIpsTextarea.disabled = true;
                allowedDirectIpsTextarea.placeholder = 'Loading...';
                
                const response = await safeFetch('/api/security/allowed-direct-ips');
                const data = await response.json();
                
                if (data.ips) {
                    allowedDirectIpsTextarea.value = data.ips.join('\n');
                } else {
                    allowedDirectIpsTextarea.value = '';
                }
            } catch (error) {
                if (allowedDirectIpsMessage) {
                    showMessage(allowedDirectIpsMessage, 'Failed to fetch allowed direct IPs: ' + error.message, false);
                }
            } finally {
                allowedDirectIpsTextarea.disabled = false;
                allowedDirectIpsTextarea.placeholder = 'Enter IPs to allow direct access, one per line\nExample:\n192.168.1.1\n10.0.0.0/24';
            }
        }
        
        async function saveAllowedDirectIps() {
            if (!allowedDirectIpsTextarea) return;
            
            try {
                if (saveAllowedDirectIpsBtn) saveAllowedDirectIpsBtn.disabled = true;
                if (allowedDirectIpsMessage) showMessage(allowedDirectIpsMessage, 'Saving...', null);
                
                const ips = allowedDirectIpsTextarea.value
                    .split('\n')
                    .map(line => line.trim())
                    .filter(line => validateInput(line, 'ip'));
                
                const response = await safeFetch('/api/security/allowed-direct-ips', {
                    method: 'POST',
                    headers: addCSRFToken({
                        'Content-Type': 'application/json'
                    }),
                    body: JSON.stringify({ ips })
                });
                
                const data = await response.json();
                
                if (data.status === 'success') {
                    showMessage(allowedDirectIpsMessage, 'Allowed direct IPs updated successfully', true);
                } else {
                    showMessage(allowedDirectIpsMessage, data.message || 'Failed to update allowed direct IPs', false);
                }
            } catch (error) {
                if (allowedDirectIpsMessage) {
                    showMessage(allowedDirectIpsMessage, 'Failed to save allowed direct IPs: ' + error.message, false);
                }
            } finally {
                if (saveAllowedDirectIpsBtn) saveAllowedDirectIpsBtn.disabled = false;
            }
        }
        
        async function saveCacheSettings() {
            if (!cacheSizeInput || !maxObjectSizeValueInput || !maxObjectSizeUnitSelect) return;
            
            try {
                if (saveCacheSettingsBtn) saveCacheSettingsBtn.disabled = true;
                if (cacheSettingsMessage) showMessage(cacheSettingsMessage, 'Saving...', null);
                
                const cacheSize = cacheSizeInput.value;
                const maxObjectSize = `${maxObjectSizeValueInput.value} ${maxObjectSizeUnitSelect.value}`;
                
                const response = await safeFetch('/api/security/cache-settings', {
                    method: 'POST',
                    headers: addCSRFToken({
                        'Content-Type': 'application/json'
                    }),
                    body: JSON.stringify({ cacheSize, maxObjectSize })
                });
                
                const data = await response.json();
                
                if (data.status === 'success') {
                    showMessage(cacheSettingsMessage, 'Cache settings updated successfully', true);
                } else {
                    showMessage(cacheSettingsMessage, data.message || 'Failed to update cache settings', false);
                }
            } catch (error) {
                if (cacheSettingsMessage) {
                    showMessage(cacheSettingsMessage, 'Failed to save cache settings: ' + error.message, false);
                }
            } finally {
                if (saveCacheSettingsBtn) saveCacheSettingsBtn.disabled = false;
            }
        }
    }
    
    // Initialize Settings Page
    function initSettingsPage() {
        // System info elements
        const squidVersionSpan = document.getElementById('squid-version');
        
        // Configuration editor elements
        const configEditor = document.getElementById('config-editor');
        const reloadConfigBtn = document.getElementById('reload-config-btn');
        const saveConfigBtn = document.getElementById('save-config-btn');
        const configEditorMessage = document.getElementById('config-editor-message');
        
        // Port Configuration
        const portInput = document.getElementById('port');
        const updatePortBtn = document.getElementById('update-port-btn');
        const configMessage = document.getElementById('config-message');
        
        // Cache Settings
        const cacheSizeInput = document.getElementById('cache-size');
        const maxObjectSizeValueInput = document.getElementById('max-object-size-value');
        const maxObjectSizeUnitSelect = document.getElementById('max-object-size-unit');
        const saveCacheSettingsBtn = document.getElementById('save-cache-settings-btn');
        const cacheSettingsMessage = document.getElementById('cache-settings-message');
        
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
        
        // System settings elements
        const squidPathInput = document.getElementById('squid-path');
        const configPathInput = document.getElementById('config-path');
        const cacheDirInput = document.getElementById('cache-dir');
        const saveSystemSettingsBtn = document.getElementById('save-system-settings-btn');
        const systemSettingsMessage = document.getElementById('system-settings-message');
        
        // Dashboard settings elements
        const refreshIntervalInput = document.getElementById('refresh-interval');
        const themeButtons = document.querySelectorAll('.theme-btn');
        const saveDashboardSettingsBtn = document.getElementById('save-dashboard-settings-btn');
        const dashboardSettingsMessage = document.getElementById('dashboard-settings-message');
        
        // User agent elements
        const badUserAgentsTextarea = document.getElementById('bad-user-agents-textarea');
        const saveBadUserAgentsBtn = document.getElementById('save-bad-user-agents-btn');
        const badUserAgentsMessage = document.getElementById('bad-user-agents-message');
        
        // Tab Navigation
        const tabButtons = document.querySelectorAll('.tab-btn');
        const tabContents = document.querySelectorAll('.tab-content');
        
        // Initialize
        fetchSystemInfo();
        fetchRawConfig();
        fetchBadUserAgents();
        loadDashboardSettings();
        fetchConfig();
        fetchSecurityFeatures();
        
        // Add event listeners
        if (reloadConfigBtn) reloadConfigBtn.addEventListener('click', fetchRawConfig);
        if (saveConfigBtn) saveConfigBtn.addEventListener('click', saveRawConfig);
        if (saveSystemSettingsBtn) saveSystemSettingsBtn.addEventListener('click', saveSystemSettings);
        if (saveDashboardSettingsBtn) saveDashboardSettingsBtn.addEventListener('click', saveDashboardSettings);
        if (saveBadUserAgentsBtn) saveBadUserAgentsBtn.addEventListener('click', saveBadUserAgents);
        if (updatePortBtn) updatePortBtn.addEventListener('click', updatePort);
        if (saveCacheSettingsBtn) saveCacheSettingsBtn.addEventListener('click', saveCacheSettings);
        
        // Event listeners for security features
        if (saveFeaturesBtn) saveFeaturesBtn.addEventListener('click', saveFeatureToggles);
        if (saveIpBlacklistBtn) saveIpBlacklistBtn.addEventListener('click', saveIpBlacklist);
        if (saveDomainBlacklistBtn) saveDomainBlacklistBtn.addEventListener('click', saveDomainBlacklist);
        if (saveAllowedDirectIpsBtn) saveAllowedDirectIpsBtn.addEventListener('click', saveAllowedDirectIps);
        
        // Tab navigation event listeners
        if (tabButtons) {
            tabButtons.forEach(button => {
                button.addEventListener('click', () => {
                    // Remove active class from all buttons
                    tabButtons.forEach(btn => btn.classList.remove('active'));
                    
                    // Add active class to clicked button
                    button.classList.add('active');
                    
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
                    }
                });
            });
        }
        
        // Add theme button listeners
        if (themeButtons) {
            themeButtons.forEach(button => {
                button.addEventListener('click', () => {
                    themeButtons.forEach(btn => btn.classList.remove('active'));
                    button.classList.add('active');
                });
            });
        }
        
        // Functions for settings page
        async function fetchSystemInfo() {
            try {
                const response = await safeFetch('/api/system/info');
                const data = await response.json();
                
                if (squidVersionSpan) {
                    squidVersionSpan.textContent = data.squidVersion || 'Unknown';
                }
                
                if (squidPathInput && configPathInput && cacheDirInput) {
                    squidPathInput.value = data.currentPaths?.squidPath || '';
                    configPathInput.value = data.currentPaths?.configPath || '';
                    cacheDirInput.value = data.currentPaths?.cacheDir || '';
                }
            } catch (error) {
                console.error('Error fetching system info:', error);
                if (squidVersionSpan) squidVersionSpan.textContent = 'Error';
            }
        }
        
        async function fetchRawConfig() {
            if (!configEditor) return;
            
            try {
                configEditor.disabled = true;
                configEditor.value = 'Loading...';
                
                const response = await safeFetch('/api/config/raw');
                const data = await response.json();
                
                if (data.content) {
                    configEditor.value = data.content;
                } else {
                    configEditor.value = '# No configuration found';
                }
            } catch (error) {
                showMessage(configEditorMessage, 'Failed to fetch configuration: ' + error.message, false);
                configEditor.value = '# Error loading configuration';
            } finally {
                configEditor.disabled = false;
            }
        }
        
        async function fetchConfig() {
            try {
                const response = await safeFetch('/api/config');
                const data = await response.json();
                
                if (data.port && portInput) {
                    portInput.value = data.port;
                }
                
                // Load cache settings if available
                if (data.cacheSize && cacheSizeInput) {
                    cacheSizeInput.value = data.cacheSize;
                }
                
                if (data.maxObjectSize && maxObjectSizeValueInput && maxObjectSizeUnitSelect) {
                    const [value, unit] = data.maxObjectSize.split(' ');
                    maxObjectSizeValueInput.value = value;
                    if (unit) {
                        maxObjectSizeUnitSelect.value = unit;
                    }
                }
            } catch (error) {
                if (configMessage) {
                    showMessage(configMessage, 'Failed to fetch configuration: ' + error.message, false);
                }
            }
        }
        
        async function updatePort() {
            if (!portInput) return;
            const port = portInput.value;
            
            if (!validateInput(port, 'port')) {
                showMessage(configMessage, 'Please enter a valid port number (1-65535)', false);
                return;
            }
            
            try {
                if (updatePortBtn) updatePortBtn.disabled = true;
                showMessage(configMessage, 'Updating...', null);
                
                const response = await safeFetch('/api/config', {
                    method: 'POST',
                    headers: addCSRFToken({
                        'Content-Type': 'application/json'
                    }),
                    body: JSON.stringify({ port })
                });
                
                const data = await response.json();
                
                if (data.status === 'success') {
                    showMessage(configMessage, data.message || 'Port updated successfully', true);
                    // Refresh status after updating port
                    setTimeout(fetchStatus, 1000);
                } else {
                    showMessage(configMessage, data.message || 'Failed to update port', false);
                }
            } catch (error) {
                showMessage(configMessage, 'Failed to update port: ' + error.message, false);
            } finally {
                if (updatePortBtn) updatePortBtn.disabled = false;
        }
    }
    
    async function saveCacheSettings() {
        if (!cacheSizeInput || !maxObjectSizeValueInput || !maxObjectSizeUnitSelect) return;
        
        try {
            if (saveCacheSettingsBtn) saveCacheSettingsBtn.disabled = true;
            if (cacheSettingsMessage) showMessage(cacheSettingsMessage, 'Saving...', null);
            
            const cacheSize = cacheSizeInput.value;
            const maxObjectSize = `${maxObjectSizeValueInput.value} ${maxObjectSizeUnitSelect.value}`;
            
            const response = await safeFetch('/api/security/cache-settings', {
                method: 'POST',
                headers: addCSRFToken({
                    'Content-Type': 'application/json'
                }),
                body: JSON.stringify({ cacheSize, maxObjectSize })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                showMessage(cacheSettingsMessage, 'Cache settings updated successfully', true);
            } else {
                showMessage(cacheSettingsMessage, data.message || 'Failed to update cache settings', false);
            }
        } catch (error) {
            if (cacheSettingsMessage) {
                showMessage(cacheSettingsMessage, 'Failed to save cache settings: ' + error.message, false);
            }
        } finally {
            if (saveCacheSettingsBtn) saveCacheSettingsBtn.disabled = false;
        }
    }
    
    async function saveRawConfig() {
        if (!configEditor) return;
        
        const content = configEditor.value;
        if (!content.trim()) {
            showMessage(configEditorMessage, 'Configuration cannot be empty', false);
            return;
        }
        
        if (!confirm('Are you sure you want to save this configuration? Invalid configurations may break your proxy.')) {
            return;
        }
        
        try {
            if (saveConfigBtn) saveConfigBtn.disabled = true;
            if (configEditorMessage) showMessage(configEditorMessage, 'Saving...', null);
            
            const response = await safeFetch('/api/config/raw', {
                method: 'POST',
                headers: addCSRFToken({
                    'Content-Type': 'application/json'
                }),
                body: JSON.stringify({ content })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                showMessage(configEditorMessage, 'Configuration saved successfully. A backup was created at ' + data.backupPath, true);
                // Reload the proxy to apply changes
                setTimeout(() => controlSquid('reload'), 1000);
            } else {
                showMessage(configEditorMessage, data.message || 'Failed to save configuration', false);
            }
        } catch (error) {
            showMessage(configEditorMessage, 'Failed to save configuration: ' + error.message, false);
        } finally {
            if (saveConfigBtn) saveConfigBtn.disabled = false;
        }
    }
    
    // Functions for security features
    async function fetchSecurityFeatures() {
        try {
            const response = await safeFetch('/api/security/feature-status');
            const features = await response.json();
            
            // Update toggle states with default HTTPS filtering OFF
            if (ipBlacklistToggle) ipBlacklistToggle.checked = features.ipBlacklist;
            if (domainBlacklistToggle) domainBlacklistToggle.checked = features.domainBlacklist;
            if (directIpToggle) directIpToggle.checked = features.directIpBlocking;
            if (userAgentToggle) userAgentToggle.checked = features.userAgentFiltering;
            if (malwareToggle) malwareToggle.checked = features.malwareBlocking;
            if (httpsFilteringToggle) httpsFilteringToggle.checked = features.httpsFiltering === true ? true : false;
            
            // Also fetch the initial data for the first tab
            fetchIpBlacklist();
        } catch (error) {
            if (featuresMessage) {
                showMessage(featuresMessage, 'Failed to fetch security features: ' + error.message, false);
            }
        }
    }
    
    async function saveFeatureToggles() {
        if (!ipBlacklistToggle) return;
        
        try {
            if (saveFeaturesBtn) saveFeaturesBtn.disabled = true;
            if (featuresMessage) showMessage(featuresMessage, 'Saving...', null);
            
            const features = {
                ipBlacklist: ipBlacklistToggle.checked,
                domainBlacklist: domainBlacklistToggle.checked,
                directIpBlocking: directIpToggle.checked,
                userAgentFiltering: userAgentToggle.checked,
                malwareBlocking: malwareToggle.checked,
                httpsFiltering: httpsFilteringToggle.checked
            };
            
            const response = await safeFetch('/api/security/feature-status', {
                method: 'POST',
                headers: addCSRFToken({
                    'Content-Type': 'application/json'
                }),
                body: JSON.stringify(features)
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                showMessage(featuresMessage, 'Security features updated successfully', true);
                // Reload the proxy to apply changes
                setTimeout(() => controlSquid('reload'), 1000);
            } else {
                showMessage(featuresMessage, data.message || 'Failed to update security features', false);
            }
        } catch (error) {
            if (featuresMessage) {
                showMessage(featuresMessage, 'Failed to save security features: ' + error.message, false);
            }
        } finally {
            if (saveFeaturesBtn) saveFeaturesBtn.disabled = false;
        }
    }
    
    async function fetchIpBlacklist() {
        if (!ipBlacklistTextarea) return;
        
        try {
            ipBlacklistTextarea.disabled = true;
            ipBlacklistTextarea.placeholder = 'Loading...';
            
            const response = await safeFetch('/api/security/blacklist-ips');
            const data = await response.json();
            
            if (data.ips) {
                ipBlacklistTextarea.value = data.ips.join('\n');
            } else {
                ipBlacklistTextarea.value = '';
            }
        } catch (error) {
            if (ipBlacklistMessage) {
                showMessage(ipBlacklistMessage, 'Failed to fetch IP blacklist: ' + error.message, false);
            }
        } finally {
            ipBlacklistTextarea.disabled = false;
            ipBlacklistTextarea.placeholder = 'Enter IPs to blacklist, one per line\nExample:\n192.168.1.100\n10.0.0.5';
        }
    }
    
    async function saveIpBlacklist() {
        if (!ipBlacklistTextarea) return;
        
        try {
            if (saveIpBlacklistBtn) saveIpBlacklistBtn.disabled = true;
            if (ipBlacklistMessage) showMessage(ipBlacklistMessage, 'Saving...', null);
            
            const ips = ipBlacklistTextarea.value
                .split('\n')
                .map(line => line.trim())
                .filter(line => validateInput(line, 'ip'));
            
            const response = await safeFetch('/api/security/blacklist-ips', {
                method: 'POST',
                headers: addCSRFToken({
                    'Content-Type': 'application/json'
                }),
                body: JSON.stringify({ ips })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                showMessage(ipBlacklistMessage, 'IP blacklist updated successfully', true);
            } else {
                showMessage(ipBlacklistMessage, data.message || 'Failed to update IP blacklist', false);
            }
        } catch (error) {
            if (ipBlacklistMessage) {
                showMessage(ipBlacklistMessage, 'Failed to save IP blacklist: ' + error.message, false);
            }
        } finally {
            if (saveIpBlacklistBtn) saveIpBlacklistBtn.disabled = false;
        }
    }
    
    async function fetchDomainBlacklist() {
        if (!domainBlacklistTextarea) return;
        
        try {
            domainBlacklistTextarea.disabled = true;
            domainBlacklistTextarea.placeholder = 'Loading...';
            
            const response = await safeFetch('/api/security/blacklist-domains');
            const data = await response.json();
            
            if (data.domains) {
                domainBlacklistTextarea.value = data.domains.join('\n');
            } else {
                domainBlacklistTextarea.value = '';
            }
        } catch (error) {
            if (domainBlacklistMessage) {
                showMessage(domainBlacklistMessage, 'Failed to fetch domain blacklist: ' + error.message, false);
            }
        } finally {
            domainBlacklistTextarea.disabled = false;
            domainBlacklistTextarea.placeholder = 'Enter domains to blacklist, one per line\nExample:\nexample.com\nads.example.org';
        }
    }
    
    async function saveDomainBlacklist() {
        if (!domainBlacklistTextarea) return;
        
        try {
            if (saveDomainBlacklistBtn) saveDomainBlacklistBtn.disabled = true;
            if (domainBlacklistMessage) showMessage(domainBlacklistMessage, 'Saving...', null);
            
            const domains = domainBlacklistTextarea.value
                .split('\n')
                .map(line => line.trim())
                .filter(line => validateInput(line, 'domain'));
            
            const response = await safeFetch('/api/security/blacklist-domains', {
                method: 'POST',
                headers: addCSRFToken({
                    'Content-Type': 'application/json'
                }),
                body: JSON.stringify({ domains })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                showMessage(domainBlacklistMessage, 'Domain blacklist updated successfully', true);
            } else {
                showMessage(domainBlacklistMessage, data.message || 'Failed to update domain blacklist', false);
            }
        } catch (error) {
            if (domainBlacklistMessage) {
                showMessage(domainBlacklistMessage, 'Failed to save domain blacklist: ' + error.message, false);
            }
        } finally {
            if (saveDomainBlacklistBtn) saveDomainBlacklistBtn.disabled = false;
        }
    }
    
    async function fetchAllowedDirectIps() {
        if (!allowedDirectIpsTextarea) return;
        
        try {
            allowedDirectIpsTextarea.disabled = true;
            allowedDirectIpsTextarea.placeholder = 'Loading...';
            
            const response = await safeFetch('/api/security/allowed-direct-ips');
            const data = await response.json();
            
            if (data.ips) {
                allowedDirectIpsTextarea.value = data.ips.join('\n');
            } else {
                allowedDirectIpsTextarea.value = '';
            }
        } catch (error) {
            if (allowedDirectIpsMessage) {
                showMessage(allowedDirectIpsMessage, 'Failed to fetch allowed direct IPs: ' + error.message, false);
            }
        } finally {
            allowedDirectIpsTextarea.disabled = false;
            allowedDirectIpsTextarea.placeholder = 'Enter IPs to allow direct access, one per line\nExample:\n192.168.1.1\n10.0.0.0/24';
        }
    }
    
    async function saveAllowedDirectIps() {
        if (!allowedDirectIpsTextarea) return;
        
        try {
            if (saveAllowedDirectIpsBtn) saveAllowedDirectIpsBtn.disabled = true;
            if (allowedDirectIpsMessage) showMessage(allowedDirectIpsMessage, 'Saving...', null);
            
            const ips = allowedDirectIpsTextarea.value
                .split('\n')
                .map(line => line.trim())
                .filter(line => validateInput(line, 'ip'));
            
            const response = await safeFetch('/api/security/allowed-direct-ips', {
                method: 'POST',
                headers: addCSRFToken({
                    'Content-Type': 'application/json'
                }),
                body: JSON.stringify({ ips })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                showMessage(allowedDirectIpsMessage, 'Allowed direct IPs updated successfully', true);
            } else {
                showMessage(allowedDirectIpsMessage, data.message || 'Failed to update allowed direct IPs', false);
            }
        } catch (error) {
            if (allowedDirectIpsMessage) {
                showMessage(allowedDirectIpsMessage, 'Failed to save allowed direct IPs: ' + error.message, false);
            }
        } finally {
            if (saveAllowedDirectIpsBtn) saveAllowedDirectIpsBtn.disabled = false;
        }
    }
    
    async function fetchBadUserAgents() {
        if (!badUserAgentsTextarea) return;
        
        try {
            badUserAgentsTextarea.disabled = true;
            badUserAgentsTextarea.placeholder = 'Loading...';
            
            const response = await safeFetch('/api/security/bad-user-agents');
            const data = await response.json();
            
            if (data.userAgents) {
                badUserAgentsTextarea.value = data.userAgents.join('\n');
            } else {
                badUserAgentsTextarea.value = '';
            }
        } catch (error) {
            showMessage(badUserAgentsMessage, 'Failed to fetch bad user agents: ' + error.message, false);
        } finally {
            badUserAgentsTextarea.disabled = false;
            badUserAgentsTextarea.placeholder = 'Enter user agents to block, one per line';
        }
    }
    
    async function saveBadUserAgents() {
        if (!badUserAgentsTextarea) return;
        
        try {
            if (saveBadUserAgentsBtn) saveBadUserAgentsBtn.disabled = true;
            if (badUserAgentsMessage) showMessage(badUserAgentsMessage, 'Saving...', null);
            
            const userAgents = badUserAgentsTextarea.value
                .split('\n')
                .map(line => line.trim())
                .filter(line => line !== '');
            
            const response = await safeFetch('/api/security/bad-user-agents', {
                method: 'POST',
                headers: addCSRFToken({
                    'Content-Type': 'application/json'
                }),
                body: JSON.stringify({ userAgents })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                showMessage(badUserAgentsMessage, 'Bad user agents updated successfully', true);
            } else {
                showMessage(badUserAgentsMessage, data.message || 'Failed to update bad user agents', false);
            }
        } catch (error) {
            showMessage(badUserAgentsMessage, 'Failed to save bad user agents: ' + error.message, false);
        } finally {
            if (saveBadUserAgentsBtn) saveBadUserAgentsBtn.disabled = false;
        }
    }
    
    async function saveSystemSettings() {
        if (!squidPathInput || !configPathInput || !cacheDirInput) return;
        
        try {
            if (saveSystemSettingsBtn) saveSystemSettingsBtn.disabled = true;
            if (systemSettingsMessage) showMessage(systemSettingsMessage, 'Saving...', null);
            
            const paths = {
                squidPath: squidPathInput.value.trim(),
                configPath: configPathInput.value.trim(),
                cacheDir: cacheDirInput.value.trim()
            };
            
            const response = await safeFetch('/api/system/paths', {
                method: 'POST',
                headers: addCSRFToken({
                    'Content-Type': 'application/json'
                }),
                body: JSON.stringify(paths)
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                showMessage(systemSettingsMessage, 'System settings updated successfully', true);
            } else {
                showMessage(systemSettingsMessage, data.message || 'Failed to update system settings', false);
            }
        } catch (error) {
            showMessage(systemSettingsMessage, 'Failed to save system settings: ' + error.message, false);
        } finally {
            if (saveSystemSettingsBtn) saveSystemSettingsBtn.disabled = false;
        }
    }
    
    function loadDashboardSettings() {
        if (!refreshIntervalInput || !themeButtons) return;
        
        // Load from localStorage if available
        const settings = JSON.parse(localStorage.getItem('dashboardSettings') || '{}');
        
        if (settings.refreshInterval) {
            refreshIntervalInput.value = settings.refreshInterval;
        } else {
            refreshIntervalInput.value = '30'; // Default
        }
        
        if (settings.theme) {
            themeButtons.forEach(btn => {
                if (btn.getAttribute('data-theme') === settings.theme) {
                    btn.classList.add('active');
                } else {
                    btn.classList.remove('active');
                }
            });
        }
    }
    
    function saveDashboardSettings() {
        if (!refreshIntervalInput || !themeButtons) return;
        
        try {
            const refreshInterval = refreshIntervalInput.value;
            let theme = 'light'; // Default
            
            themeButtons.forEach(btn => {
                if (btn.classList.contains('active')) {
                    theme = btn.getAttribute('data-theme');
                }
            });
            
            const settings = {
                refreshInterval,
                theme
            };
            
            // Save to localStorage
            localStorage.setItem('dashboardSettings', JSON.stringify(settings));
            
            // Apply settings
            document.documentElement.setAttribute('data-theme', theme);
            
            showMessage(dashboardSettingsMessage, 'Dashboard settings saved successfully', true);
        } catch (error) {
            showMessage(dashboardSettingsMessage, 'Failed to save dashboard settings: ' + error.message, false);
        }
    }
}
    
    // Initialize Logs Page
    function initLogsPage() {
        // Elements
        const logButtons = document.querySelectorAll('.log-btn');
        const logTitle = document.getElementById('log-title');
        const logContent = document.getElementById('log-content');
        const logTotalLines = document.getElementById('log-total-lines');
        const logErrors = document.getElementById('log-errors');
        const logSize = document.getElementById('log-size');
        const logLastUpdated = document.getElementById('log-last-updated');
        const logLinesSelect = document.getElementById('log-lines');
        const autoRefreshSelect = document.getElementById('auto-refresh');
        const refreshLogsBtn = document.getElementById('refresh-logs-btn');
        const searchLogsToggle = document.getElementById('search-logs-toggle');
        const searchBox = document.getElementById('search-box');
        const searchInput = document.getElementById('search-input');
        const searchBtn = document.getElementById('search-btn');
        const downloadCurrentLogBtn = document.getElementById('download-current-log-btn');
        const clearLogBtn = document.getElementById('clear-log-btn');
        const generateAnalysisBtn = document.getElementById('generate-analysis-btn');
        
        // Charts placeholders (would need a charting library in production)
        const topDomainsChart = document.getElementById('top-domains-chart');
        const statusCodesChart = document.getElementById('status-codes-chart');
        const requestMethodsChart = document.getElementById('request-methods-chart');
        const trafficByHourChart = document.getElementById('traffic-by-hour-chart');
        
        // State variables
        let currentLogType = 'access';
        let autoRefreshInterval = null;
        
        // Initialize
        fetchLogs(currentLogType);
        
        // Set up auto refresh based on select
        if (autoRefreshSelect) {
            autoRefreshSelect.addEventListener('change', setupAutoRefresh);
            setupAutoRefresh(); // Initialize on page load
        }
        
        // Event listeners
        if (logButtons) {
            logButtons.forEach(button => {
                button.addEventListener('click', () => {
                    // Update active state
                    logButtons.forEach(btn => btn.classList.remove('active'));
                    button.classList.add('active');
                    
                    // Get log type
                    currentLogType = button.getAttribute('data-log');
                    
                    // Update title
                    if (logTitle) {
                        logTitle.textContent = button.textContent.trim();
                    }
                    
                    // Fetch logs
                    fetchLogs(currentLogType);
                });
            });
        }
        
        if (refreshLogsBtn) {
            refreshLogsBtn.addEventListener('click', () => fetchLogs(currentLogType));
        }
        
        if (searchLogsToggle) {
            searchLogsToggle.addEventListener('click', () => {
                if (searchBox) {
                    searchBox.classList.toggle('hidden');
                }
            });
        }
        
        if (searchBtn && searchInput) {
            searchBtn.addEventListener('click', searchLogs);
        }
        
        if (downloadCurrentLogBtn) {
            downloadCurrentLogBtn.addEventListener('click', () => downloadLog(currentLogType));
        }
        
        if (clearLogBtn) {
            clearLogBtn.addEventListener('click', () => clearLog(currentLogType));
        }
        
        if (generateAnalysisBtn) {
            generateAnalysisBtn.addEventListener('click', () => generateLogAnalysis(currentLogType));
        }
        
        // Functions for logs page
        function setupAutoRefresh() {
            if (!autoRefreshSelect) return;
            
            // Clear existing interval
            if (autoRefreshInterval) {
                clearInterval(autoRefreshInterval);
                autoRefreshInterval = null;
            }
            
            const refreshSeconds = parseInt(autoRefreshSelect.value, 10);
            if (refreshSeconds > 0) {
                autoRefreshInterval = setInterval(() => {
                    fetchLogs(currentLogType);
                }, refreshSeconds * 1000);
            }
        }
        
        async function fetchLogs(logType) {
            if (!logContent) return;
            
            try {
                logContent.innerHTML = '<div class="text-center p-8 text-gray-500">Loading logs...</div>';
                if (refreshLogsBtn) refreshLogsBtn.disabled = true;
                
                const lines = logLinesSelect ? parseInt(logLinesSelect.value, 10) : 100;
                const response = await safeFetch(`/api/logs/${logType}?lines=${lines}`);
                const data = await response.json();
                
                // Update stats
                if (logTotalLines) logTotalLines.textContent = data.totalLines || '0';
                if (logErrors) logErrors.textContent = data.errors || '0';
                if (logSize) logSize.textContent = data.size || '0 KB';
                if (logLastUpdated) logLastUpdated.textContent = data.lastModified || 'Never';
                
                // Update content
                if (data.content && Array.isArray(data.content)) {
                    if (data.content.length > 0) {
                        const logHtml = data.content.map(line => {
                            let lineClass = 'log-line';
                            if (line.includes(' ERROR ') || line.includes(' FATAL ')) {
                                lineClass += ' log-error';
                            } else if (line.includes(' WARNING ')) {
                                lineClass += ' log-warning';
                            }
                            return `<div class="${lineClass}">${escapeHtml(line)}</div>`;
                        }).join('');
                        
                        logContent.innerHTML = `<div class="log-lines">${logHtml}</div>`;
                    } else {
                        logContent.innerHTML = '<div class="text-center p-8 text-gray-500">Log is empty</div>';
                    }
                } else {
                    logContent.innerHTML = `<div class="text-center p-8 text-gray-500">${data.content || 'No logs available'}</div>`;
                }
            } catch (error) {
                logContent.innerHTML = `<div class="text-center p-8 text-red-500">Error loading logs: ${error.message}</div>`;
            } finally {
                if (refreshLogsBtn) refreshLogsBtn.disabled = false;
            }
        }
        
        function searchLogs() {
            if (!searchInput || !logContent) return;
            
            const searchTerm = searchInput.value.trim();
            if (!searchTerm) return;
            
            const caseSensitive = document.getElementById('case-sensitive')?.checked || false;
            const wholeWord = document.getElementById('whole-word')?.checked || false;
            const useRegex = document.getElementById('regex-search')?.checked || false;
            
            // Get all log lines
            const logLines = logContent.querySelectorAll('.log-line');
            
            // Clear previous highlights
            logLines.forEach(line => {
                line.innerHTML = escapeHtml(line.textContent || '');
                line.classList.remove('search-highlight');
            });
            
            // Prepare search function
            let searchFunction;
            
            if (useRegex) {
                try {
                    const regex = new RegExp(searchTerm, caseSensitive ? '' : 'i');
                    searchFunction = text => regex.test(text);
                } catch (e) {
                    alert('Invalid regular expression');
                    return;
                }
            } else if (wholeWord) {
                const wordBoundary = '\\b';
                const term = escapeRegExp(searchTerm);
                const regex = new RegExp(wordBoundary + term + wordBoundary, caseSensitive ? '' : 'i');
                searchFunction = text => regex.test(text);
            } else {
                searchFunction = caseSensitive 
                    ? text => text.includes(searchTerm)
                    : text => text.toLowerCase().includes(searchTerm.toLowerCase());
            }
            
            // Highlight matching lines
            let matchCount = 0;
            logLines.forEach(line => {
                const lineText = line.textContent || '';
                if (searchFunction(lineText)) {
                    line.classList.add('search-highlight');
                    matchCount++;
                    
                    // Highlight the matching text
                    if (!useRegex) {
                        const term = escapeRegExp(searchTerm);
                        const regex = new RegExp(term, caseSensitive ? 'g' : 'gi');
                        line.innerHTML = escapeHtml(lineText).replace(
                            regex, 
                            match => `<span class="highlight">${match}</span>`
                        );
                    }
                }
            });
            
            // Scroll to first match
            const firstMatch = logContent.querySelector('.search-highlight');
            if (firstMatch) {
                firstMatch.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
            
            alert(`Found ${matchCount} matching lines`);
        }
        
        async function downloadLog(logType) {
            try {
                if (downloadCurrentLogBtn) downloadCurrentLogBtn.classList.add('animate-spin');
                
                const a = document.createElement('a');
                a.href = `/api/logs/${logType}/download`;
                a.download = `${logType}.log`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
            } catch (error) {
                alert('Failed to download log: ' + error.message);
            } finally {
                if (downloadCurrentLogBtn) downloadCurrentLogBtn.classList.remove('animate-spin');
            }
        }
        
        async function clearLog(logType) {
            if (!confirm(`Are you sure you want to clear the ${logType} log? This action cannot be undone.`)) {
                return;
            }
            
            try {
                if (clearLogBtn) clearLogBtn.classList.add('animate-spin');
                
                const response = await safeFetch(`/api/logs/${logType}/clear`, {
                    method: 'POST',
                    headers: addCSRFToken()
                });
                
                const data = await response.json();
                
                if (data.status === 'success') {
                    fetchLogs(logType);
                } else {
                    alert('Failed to clear log: ' + (data.message || 'Unknown error'));
                }
            } catch (error) {
                alert('Failed to clear log: ' + error.message);
            } finally {
                if (clearLogBtn) clearLogBtn.classList.remove('animate-spin');
            }
        }
        
        async function generateLogAnalysis(logType) {
            try {
                if (generateAnalysisBtn) generateAnalysisBtn.classList.add('animate-spin');
                
                // Display "loading" text in chart containers
                const chartContainers = [
                    topDomainsChart, 
                    statusCodesChart, 
                    requestMethodsChart, 
                    trafficByHourChart
                ];
                
                chartContainers.forEach(container => {
                    if (container) {
                        container.innerHTML = '<div class="flex items-center justify-center h-full"><span class="text-gray-500">Loading analysis data...</span></div>';
                    }
                });
                
                const response = await safeFetch(`/api/logs/${logType}/analysis`);
                const data = await response.json();
                
                // For a real implementation, you would use a charting library here
                // This is just a placeholder to demonstrate the concept
                
                if (topDomainsChart) {
                    topDomainsChart.innerHTML = generateSampleChart(data.topDomains, 'domain', 'requests');
                }
                
                if (statusCodesChart) {
                    statusCodesChart.innerHTML = generateSampleChart(data.statusCodes, 'status code', 'count');
                }
                
                if (requestMethodsChart) {
                    requestMethodsChart.innerHTML = generateSampleChart(data.requestMethods, 'method', 'count');
                }
                
                if (trafficByHourChart) {
                    trafficByHourChart.innerHTML = generateSampleChart(data.trafficByHour, 'hour', 'requests');
                }
            } catch (error) {
                const errorMsg = '<div class="flex items-center justify-center h-full"><span class="text-red-500">Error loading analysis data</span></div>';
                
                if (topDomainsChart) topDomainsChart.innerHTML = errorMsg;
                if (statusCodesChart) statusCodesChart.innerHTML = errorMsg;
                if (requestMethodsChart) requestMethodsChart.innerHTML = errorMsg;
                if (trafficByHourChart) trafficByHourChart.innerHTML = errorMsg;
                
                console.error('Error generating log analysis:', error);
            } finally {
                if (generateAnalysisBtn) generateAnalysisBtn.classList.remove('animate-spin');
            }
        }
        
        // Helper function to generate a simple visual representation of data
        function generateSampleChart(data, keyLabel, valueLabel) {
            if (!data || Object.keys(data).length === 0) {
                return '<div class="flex items-center justify-center h-full"><span class="text-gray-500">No data available</span></div>';
            }
            
            let html = '<div class="overflow-auto max-h-full">';
            html += '<table class="w-full text-sm">';
            html += `<tr><th class="text-left p-1">${keyLabel}</th><th class="text-left p-1">${valueLabel}</th><th class="w-full p-1">Distribution</th></tr>`;
            
            // Find the max value for scaling
            const maxValue = Math.max(...Object.values(data));
            
            // Generate table rows
            Object.entries(data).forEach(([key, value]) => {
                const percentage = Math.round((value / maxValue) * 100);
                html += `<tr>
                    <td class="p-1">${escapeHtml(key)}</td>
                    <td class="p-1">${value}</td>
                    <td class="p-1">
                        <div class="bg-gray-200 h-4 rounded-full w-full">
                            <div class="bg-primary h-4 rounded-full" style="width: ${percentage}%"></div>
                        </div>
                    </td>
                </tr>`;
            });
            
            html += '</table></div>';
            return html;
        }
        
        // Helper function to escape HTML
        function escapeHtml(unsafe) {
            return unsafe
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }
        
        // Helper function to escape regex special characters
        function escapeRegExp(string) {
            return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        }
    }
});