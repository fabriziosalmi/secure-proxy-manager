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
        validate: value => {
            // Handle comment lines
            if (value.startsWith('#')) return true;
            
            // Handle empty values
            if (!value.trim()) return true;
            
            // Handle CIDR notation
            if (value.includes('/')) {
                const [ipPart, cidrPart] = value.split('/', 2);
                const cidrNum = parseInt(cidrPart, 10);
                
                // Check if CIDR part is valid
                if (isNaN(cidrNum)) return false;
                
                // IPv4 CIDR: 0-32
                if (ipPart.includes('.') && (cidrNum < 0 || cidrNum > 32)) return false;
                
                // IPv6 CIDR: 0-128
                if (ipPart.includes(':') && (cidrNum < 0 || cidrNum > 128)) return false;
                
                // Now validate the IP part
                return ipPart.includes('.') ? 
                    /^(\d{1,3}\.){3}\d{1,3}$/.test(ipPart) : 
                    /^([0-9a-fA-F]{1,4}:){1,7}([0-9a-fA-F]{1,4})?$/.test(ipPart);
            }
            
            // Regular IPv4/IPv6 validation
            return /^(\d{1,3}\.){3}\d{1,3}$/.test(value) || 
                   /^([0-9a-fA-F]{1,4}:){1,7}([0-9a-fA-F]{1,4})$/.test(value);
        },
        message: 'Please enter a valid IP address (IPv4, IPv6, or CIDR notation)'
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
                // Accept comment lines
                if (input.startsWith('#')) return true;
                
                // Handle empty values
                if (!input.trim()) return true;
                
                // Handle CIDR notation
                if (input.includes('/')) {
                    const [ipPart, cidrPart] = input.split('/', 2);
                    const cidrNum = parseInt(cidrPart, 10);
                    
                    // Check CIDR range validity
                    if (isNaN(cidrNum)) return false;
                    
                    if (ipPart.includes('.') && (cidrNum < 0 || cidrNum > 32)) return false;
                    if (ipPart.includes(':') && (cidrNum < 0 || cidrNum > 128)) return false;
                    
                    // Validate IP part
                    return ipPart.includes('.') ? 
                        /^(\d{1,3}\.){3}\d{1,3}$/.test(ipPart) : 
                        /^([0-9a-fA-F]{1,4}:){1,7}([0-9a-fA-F]{1,4})?$/.test(ipPart);
                }
                
                // Basic IP validation (IPv4 and IPv6)
                return /^(\d{1,3}\.){3}\d{1,3}$/.test(input) || 
                       /^([0-9a-fA-F]{1,4}:){1,7}([0-9a-fA-F]{1,4})$/.test(input);
            case 'domain':
                // Accept comment lines
                if (input.startsWith('#')) return true;
                
                // Handle empty values
                if (!input.trim()) return true;
                
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

    // Squid config editor syntax highlighting
    function applyConfigSyntaxHighlighting() {
        const configEditor = document.getElementById('config-editor');
        if (!configEditor) return;
        
        let content = configEditor.value;
        if (!content) return;
        
        // Create a temporary div for HTML conversion
        const tempDiv = document.createElement('div');
        
        // Escape HTML
        content = content.replace(/&/g, '&amp;')
                         .replace(/</g, '&lt;')
                         .replace(/>/g, '&gt;');
        
        // Highlight comments
        content = content.replace(/(#.*)$/gm, '<span class="config-comment">$1</span>');
        
        // Highlight directives and values
        content = content.replace(/^(\s*[a-zA-Z_]+)(\s+)([^#\n]+)/gm, 
            '<span class="config-directive">$1</span>$2<span class="config-value">$3</span>');
        
        // Highlight symbols
        content = content.replace(/(\{|\}|\(|\)|\[|\])/g, '<span class="config-symbol">$1</span>');
        
        // Create a pre element with the highlighted code
        const highlightedCode = document.createElement('pre');
        highlightedCode.className = 'config-highlighted';
        highlightedCode.innerHTML = content;
        
        // Replace the textarea with the highlighted code when not focused
        configEditor.addEventListener('blur', function() {
            const parent = configEditor.parentNode;
            highlightedCode.style.height = configEditor.offsetHeight + 'px';
            configEditor.style.display = 'none';
            parent.insertBefore(highlightedCode, configEditor);
        });
        
        // Switch back to editable textarea when clicking on the highlighted code
        highlightedCode.addEventListener('click', function() {
            highlightedCode.remove();
            configEditor.style.display = 'block';
            configEditor.focus();
        });
        
        // Update highlighting when content changes
        configEditor.addEventListener('input', function() {
            if (document.contains(highlightedCode)) {
                highlightedCode.remove();
            }
        });
    }

    // Update security feature status badges
    function updateFeatureStatusBadges() {
        const statusElements = {
            'ip-blacklist-status': document.getElementById('ip-blacklist-toggle'),
            'domain-blacklist-status': document.getElementById('domain-blacklist-toggle'),
            'direct-ip-status': document.getElementById('direct-ip-toggle'),
            'user-agent-status': document.getElementById('user-agent-toggle'),
            'malware-status': document.getElementById('malware-toggle'),
            'https-filtering-status': document.getElementById('https-filtering-toggle')
        };
        
        const countElements = {
            'ip-blacklist': document.getElementById('ip-blacklist-count'),
            'domain-blacklist': document.getElementById('domain-blacklist-count'),
            'allowed-direct-ips': document.getElementById('allowed-direct-ips-count')
        };
        
        // Update status badges based on toggle state and count
        Object.entries(statusElements).forEach(([statusId, toggleElement]) => {
            if (!toggleElement) return;
            
            const statusBadge = document.getElementById(statusId);
            if (!statusBadge) return;
            
            const isEnabled = toggleElement.checked;
            const countElement = Object.entries(countElements).find(([key]) => statusId.includes(key))?.[1];
            const count = countElement ? parseInt(countElement.textContent || '0', 10) : null;
            
            statusBadge.textContent = isEnabled ? 'Enabled' : 'Disabled';
            statusBadge.className = 'feature-status-badge';
            
            if (isEnabled) {
                if (count !== null && count === 0) {
                    // Enabled but no items (partial)
                    statusBadge.classList.add('status-partial');
                    statusBadge.textContent = 'No Items';
                } else {
                    // Fully enabled
                    statusBadge.classList.add('status-enabled');
                }
            } else {
                // Disabled
                statusBadge.classList.add('status-disabled');
            }
        });
    }

    // Update dashboard security feature indicators
    function updateDashboardSecurityFeatures(features) {
        // Update feature indicators on the dashboard page
        const featureElements = {
            'feature-ip-blacklist': 'ipBlacklist',
            'feature-domain-blacklist': 'domainBlacklist',
            'feature-direct-ip': 'directIpBlocking',
            'feature-user-agent': 'userAgentFiltering',
            'feature-malware': 'malwareBlocking',
            'feature-https': 'httpsFiltering'
        };
        
        // Update DOM elements if they exist
        Object.entries(featureElements).forEach(([elementId, featureKey]) => {
            const element = document.getElementById(elementId);
            if (!element) return;
            
            const statusIndicator = element.querySelector('.rounded-full');
            if (!statusIndicator) return;
            
            const isEnabled = features[featureKey];
            
            // Reset classes
            statusIndicator.className = 'w-3 h-3 rounded-full mr-2';
            
            if (isEnabled) {
                // Green for enabled
                statusIndicator.classList.add('bg-green-500');
            } else {
                // Gray for disabled
                statusIndicator.classList.add('bg-gray-400');
            }
        });
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
        
        // Initialize
        fetchStatus();
        // Fetch system info for About card
        (async function fetchDashboardSystemInfo() {
            try {
                const resp = await safeFetch('/api/system/info');
                const info = await resp.json();
                const verEl = document.getElementById('squid-version');
                if (verEl && info.squidVersion) verEl.textContent = info.squidVersion;
            } catch (e) {
                const verEl = document.getElementById('squid-version');
                if (verEl) verEl.textContent = 'Error';
            }
        })();
        
        // Event listeners for basic controls
        if (startBtn) startBtn.addEventListener('click', () => controlSquid('start'));
        if (stopBtn) stopBtn.addEventListener('click', () => controlSquid('stop'));
        if (restartBtn) restartBtn.addEventListener('click', () => controlSquid('restart'));
        if (reloadBtn) reloadBtn.addEventListener('click', () => controlSquid('reload'));
        if (refreshStatusBtn) refreshStatusBtn.addEventListener('click', () => fetchStatus());
        
        // Real-time Monitoring - Initialize if elements exist
        initRealTimeMonitoring();
        
        // Initialize security features
        initSecurityFeatures();
        
        // Initialize log controls
        initLogControls();
        
        // Initialize tab navigation
        initTabNavigation();
        
        // Component initialization functions
        function initRealTimeMonitoring() {
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
            
            // Check if we're on the right page with required elements
            const isMonitoringPage = connectionsCount && connectionsBar && clientsCount;
            if (!isMonitoringPage) {
                console.log("Not on monitoring page or elements not found");
                return; // Exit if elements don't exist or not on dashboard page
            }
            
            console.log("Initializing real-time monitoring");
            
            // Initialize
            fetchRealTimeStats();
            
            // Event listeners for real-time monitoring
            if (refreshConnectionsBtn) refreshConnectionsBtn.addEventListener('click', fetchRealTimeStats);
            if (toggleAutoRefresh) toggleAutoRefresh.addEventListener('click', toggleConnectionsAutoRefresh);
            
            function toggleConnectionsAutoRefresh() {
                connectionsAutoRefresh = !connectionsAutoRefresh;
                
                if (autoRefreshStatus) {
                    autoRefreshStatus.textContent = connectionsAutoRefresh ? 'On' : 'Off';
                }
                
                if (connectionsAutoRefresh) {
                    // Start auto-refresh (every 5 seconds)
                    connectionsRefreshInterval = setInterval(fetchRealTimeStats, 5000);
                    console.log("Auto-refresh started");
                } else {
                    // Stop auto-refresh
                    if (connectionsRefreshInterval) {
                        clearInterval(connectionsRefreshInterval);
                        connectionsRefreshInterval = null;
                        console.log("Auto-refresh stopped");
                    }
                }
            }
            
            async function fetchRealTimeStats() {
                if (!connectionsCount || !clientsCount) return;
                
                try {
                    console.log("Fetching real-time stats...");
                    if (refreshConnectionsBtn) refreshConnectionsBtn.classList.add('animate-spin');
                    
                    // Add force refresh parameter to avoid cached data
                    const response = await safeFetch('/api/stats/realtime?refresh=true');
                    if (!response.ok) {
                        throw new Error(`Server returned ${response.status}: ${response.statusText}`);
                    }
                    
                    const data = await response.json();
                    console.log("Real-time stats received:", data);
                    
                    if (data.status === 'error') {
                        throw new Error(data.message || 'Unknown error fetching stats');
                    }
                    
                    // Update connections count
                    const connections = parseInt(data.connections) || 0;
                    const maxConnections = parseInt(data.maxConnections) || 1000;
                    const connectionPercentage = Math.min(100, Math.round((connections / maxConnections) * 100));
                    
                    if (connectionsCount) connectionsCount.textContent = connections;
                    if (connectionsBar) {
                        connectionsBar.style.width = `${connectionPercentage}%`;
                        updateBarColors(connectionsBar, connectionPercentage);
                    }
                    if (connectionsLimit) connectionsLimit.textContent = maxConnections;
                    
                    // Update clients count
                    const clients = parseInt(data.clients) || 0;
                    const maxClients = parseInt(data.maxClients) || 100;
                    const clientPercentage = Math.min(100, Math.round((clients / maxClients) * 100));
                    
                    if (clientsCount) clientsCount.textContent = clients;
                    if (clientsBar) {
                        clientsBar.style.width = `${clientPercentage}%`;
                        updateBarColors(clientsBar, clientPercentage);
                    }
                    if (clientsLimit) clientsLimit.textContent = maxClients;
                    
                    // Update peak values
                    peakConnectionsValue = Math.max(peakConnectionsValue, connections);
                    peakClientsValue = Math.max(peakClientsValue, clients);
                    
                    if (peakConnections) peakConnections.textContent = peakConnectionsValue;
                    if (peakClients) peakClients.textContent = peakClientsValue;
                    
                    // Update system info if elements exist
                    const cpuUsageEl = document.getElementById('cpu-usage');
                    const memoryUsageEl = document.getElementById('memory-usage');
                    const diskUsageEl = document.getElementById('disk-usage');
                    const processIdEl = document.getElementById('process-id');
                    
                    if (cpuUsageEl) cpuUsageEl.textContent = `${parseFloat(data.cpu).toFixed(1) || 0}%`;
                    if (memoryUsageEl) memoryUsageEl.textContent = `${parseFloat(data.memory).toFixed(1) || 0}% (${data.memoryMB || 0} MB)`;
                    if (diskUsageEl) diskUsageEl.textContent = `${data.diskUsageMB || 0} MB`;
                    if (processIdEl) processIdEl.textContent = data.pid > 0 ? data.pid : 'Not running';
                    
                    // Update last updated time
                    if (lastUpdateTime) {
                        const now = new Date();
                        lastUpdateTime.textContent = now.toLocaleTimeString();
                    }
                    
                } catch (error) {
                    console.error('Error fetching real-time stats:', error);
                    
                    // Show error state in a more informative way
                    if (connectionsCount) connectionsCount.textContent = '?';
                    if (clientsCount) clientsCount.textContent = '?';
                    if (lastUpdateTime) lastUpdateTime.textContent = 'Error: ' + error.message;
                    
                    // Reset progress bars
                    if (connectionsBar) {
                        connectionsBar.style.width = '0%';
                        connectionsBar.className = 'progress-bar progress-low';
                    }
                    if (clientsBar) {
                        clientsBar.style.width = '0%';
                        clientsBar.className = 'progress-bar progress-low';
                    }
                    
                    // Clear system metrics
                    const cpuUsageEl = document.getElementById('cpu-usage');
                    const memoryUsageEl = document.getElementById('memory-usage');
                    const diskUsageEl = document.getElementById('disk-usage');
                    const processIdEl = document.getElementById('process-id');
                    
                    if (cpuUsageEl) cpuUsageEl.textContent = 'N/A';
                    if (memoryUsageEl) memoryUsageEl.textContent = 'N/A';
                    if (diskUsageEl) diskUsageEl.textContent = 'N/A';
                    if (processIdEl) processIdEl.textContent = 'Not running';
                    
                    // Show toast notification about the error
                    if (typeof toast !== 'undefined') {
                        toast.show('Error fetching monitoring data. Check console for details.', 'error');
                    }
                } finally {
                    if (refreshConnectionsBtn) refreshConnectionsBtn.classList.remove('animate-spin');
                }
            }
            
            function updateBarColors(barElement, percentage) {
                barElement.classList.remove('progress-low', 'progress-medium', 'progress-high', 'progress-critical');
                
                if (percentage < 50) {
                    barElement.classList.add('progress-low');
                } else if (percentage < 75) {
                    barElement.classList.add('progress-medium');
                } else if (percentage < 90) {
                    barElement.classList.add('progress-high');
                } else {
                    barElement.classList.add('progress-critical');
                }
            }
        }
        
        function initSecurityFeatures() {
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
            
            if (!ipBlacklistToggle) return; // Exit if elements don't exist
            
            fetchSecurityFeatures();
            
            // Event listeners
            if (saveFeaturesBtn) saveFeaturesBtn.addEventListener('click', saveFeatureToggles);
            if (saveIpBlacklistBtn) saveIpBlacklistBtn.addEventListener('click', saveIpBlacklist);
            if (saveDomainBlacklistBtn) saveDomainBlacklistBtn.addEventListener('click', saveDomainBlacklist);
            if (saveAllowedDirectIpsBtn) saveAllowedDirectIpsBtn.addEventListener('click', saveAllowedDirectIps);
        }
        
        function initLogControls() {
            // Log Controls
            const downloadLogsBtn = document.getElementById('download-logs-btn');
            const clearLogsBtn = document.getElementById('clear-logs-btn');
            
            if (!downloadLogsBtn && !clearLogsBtn) return; // Exit if elements don't exist
            
            // Event listeners
            if (downloadLogsBtn) downloadLogsBtn.addEventListener('click', downloadLogs);
            if (clearLogsBtn) clearLogsBtn.addEventListener('click', clearLogs);
        }
        
        function initTabNavigation() {
            // Tab Navigation
            const tabButtons = document.querySelectorAll('.tab-btn');
            
            if (!tabButtons.length) return; // Exit if elements don't exist
            
            // Tab navigation event listeners
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
                        content.classList.add('hidden');
                        content.classList.remove('active');
                    });
                    
                    // Show the selected tab content
                    const activeTab = document.getElementById(tabName + '-tab');
                    if (activeTab) {
                        activeTab.classList.remove('hidden');
                        activeTab.classList.add('active');
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
        
        // Cache Settings
        const cacheSizeInput = document.getElementById('cache-size');
        const maxObjectSizeValueInput = document.getElementById('max-object-size-value');
        const maxObjectSizeUnitSelect = document.getElementById('max-object-size-unit');
        const saveCacheSettingsBtn = document.getElementById('save-cache-settings-btn');
        const cacheSettingsMessage = document.getElementById('cache-settings-message');
        
        // Security Feature Elements (already defined in initSettingsPage)
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
        if (saveDashboardSettingsBtn) saveDashboardSettingsBtn.addEventListener('click', saveDashboardSettings);
        if (saveBadUserAgentsBtn) saveBadUserAgentsBtn.addEventListener('click', saveBadUserAgents);
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
                        content.classList.add('hidden');
                        content.classList.remove('active');
                    });
                    
                    // Show the selected tab content
                    const activeTab = document.getElementById(tabName + '-tab');
                    if (activeTab) {
                        activeTab.classList.remove('hidden');
                        activeTab.classList.add('active');
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
                    const theme = button.getAttribute('data-theme');
                    
                    // Update button appearance
                    themeButtons.forEach(btn => btn.classList.remove('active'));
                    button.classList.add('active');
                    
                    // Update theme in localStorage
                    localStorage.setItem('theme', theme);
                    
                    // Apply theme to document
                    setTheme(theme);
                });
            });
        }
        
        // Functions for settings page
        async function fetchSystemInfo() {
            try {
                const response = await safeFetch('/api/system/info');
                const data = await response.json();
                
                if (squidVersionSpan && data.squidVersion) {
                    squidVersionSpan.textContent = data.squidVersion;
                }
            } catch (error) {
                console.error('Error fetching system info:', error);
                if (squidVersionSpan) {
                    squidVersionSpan.textContent = 'Error loading version';
                }
            }
        }
        
        async function fetchConfig() {
            try {
                const response = await safeFetch('/api/config');
                const data = await response.json();
                
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
                if (cacheSettingsMessage) {
                    showMessage(cacheSettingsMessage, 'Failed to fetch configuration: ' + error.message, false);
                }
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
                
                // Update status badges
                updateFeatureStatusBadges();
                
                // Update dashboard indicators if on the dashboard page
                updateDashboardSecurityFeatures(features);
                
                // Also fetch the initial data for blacklist counts
                fetchIpBlacklist();
                fetchDomainBlacklist();
                fetchAllowedDirectIps();
                
                // Initialize certificate status if on settings page
                if (document.getElementById('cert-status')) {
                    fetchCertificateStatus();
                }
                
                // Apply syntax highlighting to Squid config editor if it exists
                if (document.getElementById('config-editor')) {
                    applyConfigSyntaxHighlighting();
                }
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
                    
                    // Update the count display if it exists
                    const countElement = document.getElementById('ip-blacklist-count');
                    if (countElement) {
                        countElement.textContent = data.ips.length;
                    }
                } else {
                    ipBlacklistTextarea.value = '';
                    const countElement = document.getElementById('ip-blacklist-count');
                    if (countElement) {
                        countElement.textContent = '0';
                    }
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
                    .filter(line => line !== '');
                
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
                    
                    // Update count on success
                    const countElement = document.getElementById('ip-blacklist-count');
                    if (countElement) {
                        countElement.textContent = ips.length;
                    }
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
                    
                    // Update the count display if it exists
                    const countElement = document.getElementById('domain-blacklist-count');
                    if (countElement) {
                        countElement.textContent = data.domains.length;
                    }
                } else {
                    domainBlacklistTextarea.value = '';
                    const countElement = document.getElementById('domain-blacklist-count');
                    if (countElement) {
                        countElement.textContent = '0';
                    }
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
                    .filter(line => line !== '');
                
                // Validate domains before sending to the API
                for (const domain of domains) {
                    if (!domain.startsWith('#') && domain.trim() && !validateInput(domain, 'domain')) {
                        showMessage(domainBlacklistMessage, `Invalid domain: ${domain}`, false);
                        if (saveDomainBlacklistBtn) saveDomainBlacklistBtn.disabled = false;
                        return;
                    }
                }
                
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
                    
                    // Update count on success
                    const countElement = document.getElementById('domain-blacklist-count');
                    if (countElement) {
                        countElement.textContent = domains.length;
                    }
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
                    
                    // Update the count display if it exists
                    const countElement = document.getElementById('allowed-direct-ips-count');
                    if (countElement) {
                        countElement.textContent = data.ips.length;
                    }
                } else {
                    allowedDirectIpsTextarea.value = '';
                    const countElement = document.getElementById('allowed-direct-ips-count');
                    if (countElement) {
                        countElement.textContent = '0';
                    }
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
                    
                    // Update the count display if it exists
                    const countElement = document.getElementById('bad-user-agents-count');
                    if (countElement) {
                        countElement.textContent = data.userAgents.length;
                    }
                } else {
                    badUserAgentsTextarea.value = '';
                    const countElement = document.getElementById('bad-user-agents-count');
                    if (countElement) {
                        countElement.textContent = '0';
                    }
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
                    
                    // Update count on success
                    const countElement = document.getElementById('bad-user-agents-count');
                    if (countElement) {
                        countElement.textContent = userAgents.length;
                    }
                } else {
                    showMessage(badUserAgentsMessage, data.message || 'Failed to update bad user agents', false);
                }
            } catch (error) {
                showMessage(badUserAgentsMessage, 'Failed to save bad user agents: ' + error.message, false);
            } finally {
                if (saveBadUserAgentsBtn) saveBadUserAgentsBtn.disabled = false;
            }
        }
        
        async function saveDashboardSettings() {
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
                logContent.innerHTML = '<div class="text-center p-8 text-gray-500"><i class="ri-loader-4-line animate-spin text-xl mr-2"></i>Loading logs...</div>';
                if (refreshLogsBtn) refreshLogsBtn.disabled = true;
                
                const lines = logLinesSelect ? parseInt(logLinesSelect.value, 10) : 100;
                const response = await safeFetch(`/api/logs/${logType}?lines=${lines}`);
                
                if (!response.ok) {
                    throw new Error(`HTTP error ${response.status}: ${response.statusText}`);
                }
                
                const data = await response.json();
                
                // Update stats
                if (logTotalLines) logTotalLines.textContent = data.totalLines || '0';
                if (logErrors) logErrors.textContent = data.errorCount || '0';
                if (logSize) logSize.textContent = formatFileSize(data.size || 0);
                
                const now = new Date();
                if (logLastUpdated) logLastUpdated.textContent = now.toLocaleTimeString();
                
                // Show/hide appropriate analysis section based on log type
                if (logType === 'access') {
                    if (document.getElementById('access-log-analysis')) {
                        document.getElementById('access-log-analysis').classList.remove('hidden');
                    }
                    if (document.getElementById('system-log-analysis')) {
                        document.getElementById('system-log-analysis').classList.add('hidden');
                    }
                } else if (logType === 'system') {
                    if (document.getElementById('access-log-analysis')) {
                        document.getElementById('access-log-analysis').classList.add('hidden');
                    }
                    if (document.getElementById('system-log-analysis')) {
                        document.getElementById('system-log-analysis').classList.remove('hidden');
                    }
                }
                
                // Update content
                if (data.content && Array.isArray(data.content)) {
                    if (data.content.length === 0) {
                        logContent.innerHTML = '<div class="text-center p-8 text-gray-500">No log entries found</div>';
                    } else {
                        let html = '';
                        
                        // Process log entries based on type
                        data.content.forEach((line, index) => {
                            let lineClass = 'log-line';
                            let lineStyle = '';
                            
                            // Add specific styling based on log type and content
                            if (logType === 'access') {
                                // Access log formatting (contains HTTP status codes)
                                if (line.includes(' 200 ') || line.includes(' 304 ')) {
                                    // Success status
                                    lineStyle = 'color: #2563eb;';
                                } else if (line.includes(' 404 ') || line.includes(' 403 ')) {
                                    // Client error
                                    lineStyle = 'color: #f59e0b;';
                                    lineClass += ' warning-line';
                                } else if (line.includes(' 500 ') || line.includes(' 502 ') || line.includes(' 503 ')) {
                                    // Server error
                                    lineStyle = 'color: #ef4444;';
                                    lineClass += ' error-line';
                                }
                            } else if (logType === 'cache' || logType === 'store' || logType === 'system') {
                                // Error and warning coloring for other logs
                                const lowerLine = line.toLowerCase();
                                if (lowerLine.includes('error') || lowerLine.includes('fatal') || lowerLine.includes('exception')) {
                                    lineStyle = 'color: #ef4444;';
                                    lineClass += ' error-line';
                                } else if (lowerLine.includes('warn') || lowerLine.includes('denied') || lowerLine.includes('invalid')) {
                                    lineStyle = 'color: #f59e0b;';
                                    lineClass += ' warning-line';
                                } else if (lowerLine.includes('info')) {
                                    lineStyle = 'color: #2563eb;';
                                    lineClass += ' info-line';
                                }
                            }
                            
                            // Add the formatted line
                            html += `<div class="${lineClass}" style="${lineStyle}" data-index="${index}">${escapeHtml(line)}</div>`;
                        });
                        
                        logContent.innerHTML = html;
                        
                        // Scroll to bottom to show newest logs
                        logContent.scrollTop = logContent.scrollHeight;
                        
                        // If analysis section is visible, update charts
                        if (!document.getElementById('analysis-section').classList.contains('hidden')) {
                            generateLogAnalysis(logType);
                        }
                    }
                } else {
                    // Handle case when content is not an array
                    logContent.innerHTML = `<div class="text-center p-8 text-gray-500">
                        No log entries returned from server. The log file may be empty or not accessible.
                    </div>`;
                }
            } catch (error) {
                console.error('Error fetching logs:', error);
                logContent.innerHTML = `<div class="text-center p-8 text-red-500">
                    <i class="ri-error-warning-line text-xl mr-2"></i>
                    Error loading logs: ${error.message}
                    <div class="mt-2">
                        <button class="btn btn-sm btn-outline" onclick="document.getElementById('refresh-logs-btn').click()">
                            Try Again
                        </button>
                    </div>
                </div>`;
            } finally {
                if (refreshLogsBtn) refreshLogsBtn.disabled = false;
            }
        }
        
        // Helper function to format file size
        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
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
                .replace(/<//g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }
        
        // Helper function to escape regex special characters
        function escapeRegExp(string) {
            return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        }
    }
    
    // SSL Certificate functions
    async function fetchCertificateStatus() {
        try {
            const certStatus = document.getElementById('cert-status');
            const certDetails = document.getElementById('cert-details');
            
            if (certStatus) certStatus.textContent = "Checking...";
            if (certDetails) certDetails.innerHTML = "<div>Loading certificate details...</div>";
            
            const response = await safeFetch('/api/security/ssl-certificate');
            const data = await response.json();
            
            if (data.status === 'success') {
                // Update certificate status
                if (certStatus) {
                    if (data.exists) {
                        certStatus.textContent = "Certificate Installed";
                        certStatus.className = "text-sm px-2 py-1 rounded cert-valid";
                    } else {
                        certStatus.textContent = "Certificate Not Found";
                        certStatus.className = "text-sm px-2 py-1 rounded cert-missing";
                    }
                }
                
                // Update certificate details
                if (certDetails && data.exists && data.certificate) {
                    const cert = data.certificate;
                    
                    // Check certificate expiration
                    const isExpired = new Date(cert.validTo) < new Date();
                    
                    certDetails.innerHTML = `
                        <div class="mb-2 ${isExpired ? 'text-red-600' : ''}">
                            <strong>Validity:</strong> ${isExpired ? 'EXPIRED' : 'Valid'}
                        </div>
                        <div class="grid grid-cols-2 gap-2">
                            <div><strong>Subject:</strong></div>
                            <div>${cert.subject}</div>
                            <div><strong>Issuer:</strong></div>
                            <div>${cert.issuer}</div>
                            <div><strong>Valid From:</strong></div>
                            <div>${cert.validFrom}</div>
                            <div><strong>Valid To:</strong></div>
                            <div>${cert.validTo}</div>
                            <div><strong>Serial Number:</strong></div>
                            <div class="font-mono text-xs break-all">${cert.serialNumber}</div>
                        </div>
                    `;
                } else if (certDetails && !data.exists) {
                    certDetails.innerHTML = `
                        <div class="text-yellow-600">
                            <i class="ri-error-warning-line mr-1"></i> 
                            No SSL certificate found. Generate a new certificate to enable HTTPS inspection.
                        </div>
                    `;
                }
            } else {
                if (certStatus) {
                    certStatus.textContent = "Error";
                    certStatus.className = "text-sm px-2 py-1 rounded bg-red-100 text-red-800";
                }
                if (certDetails) {
                    certDetails.innerHTML = `<div class="text-red-600">Failed to check certificate status: ${data.message || 'Unknown error'}</div>`;
                }
            }
        } catch (error) {
            console.error('Error fetching certificate status:', error);
            if (document.getElementById('cert-status')) {
                document.getElementById('cert-status').textContent = "Error";
                document.getElementById('cert-status').className = "text-sm px-2 py-1 rounded bg-red-100 text-red-800";
            }
            if (document.getElementById('cert-details')) {
                document.getElementById('cert-details').innerHTML = `<div class="text-red-600">Failed to check certificate status: ${error.message}</div>`;
            }
        }
    }

    async function generateCertificate() {
        try {
            const generateCertBtn = document.getElementById('generate-cert-btn');
            const certOperationMessage = document.getElementById('cert-operation-message');
            
            if (generateCertBtn) generateCertBtn.disabled = true;
            if (certOperationMessage) showMessage(certOperationMessage, 'Generating certificate...', null);
            
            // Prompt for common name
            const commonName = prompt('Enter common name for the certificate (e.g., your organization name):', 'Secure Proxy CA');
            if (!commonName) {
                if (generateCertBtn) generateCertBtn.disabled = false;
                if (certOperationMessage) showMessage(certOperationMessage, 'Certificate generation cancelled', false);
                return;
            }
            
            const response = await safeFetch('/api/security/ssl-certificate/generate', {
                method: 'POST',
                headers: addCSRFToken({
                    'Content-Type': 'application/json'
                }),
                body: JSON.stringify({
                    commonName,
                    organization: 'Secure Proxy',
                    validDays: 3650 // 10 years
                })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                if (certOperationMessage) showMessage(certOperationMessage, 'Certificate generated successfully', true);
                
                // Enable the download button
                const downloadCertBtn = document.getElementById('download-cert-btn');
                if (downloadCertBtn) downloadCertBtn.disabled = false;
                
                // Refresh the certificate status
                fetchCertificateStatus();
                
                // Also update the HTTPS filtering toggle if it exists
                const httpsFilteringToggle = document.getElementById('https-filtering-toggle');
                if (httpsFilteringToggle) {
                    httpsFilteringToggle.checked = true;
                    
                    // Optionally save the feature toggle state
                    const saveBtn = document.getElementById('save-features-btn');
                    if (saveBtn && confirm('Do you want to enable HTTPS filtering with the new certificate?')) {
                        saveBtn.click();
                    }
                }
            } else {
                if (certOperationMessage) showMessage(certOperationMessage, `Failed to generate certificate: ${data.message || 'Unknown error'}`, false);
            }
        } catch (error) {
            console.error('Error generating certificate:', error);
            const certOperationMessage = document.getElementById('cert-operation-message');
            if (certOperationMessage) showMessage(certOperationMessage, `Failed to generate certificate: ${error.message}`, false);
        } finally {
            const generateCertBtn = document.getElementById('generate-cert-btn');
            if (generateCertBtn) generateCertBtn.disabled = false;
        }
    }

    async function downloadCertificate() {
        try {
            const downloadCertBtn = document.getElementById('download-cert-btn');
            if (downloadCertBtn) downloadCertBtn.disabled = true;
            
            // Create a hidden download link
            const a = document.createElement('a');
            a.href = `/api/security/ssl-certificate/download`;
            a.download = 'secure-proxy-ca.crt';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            
            // Show success message
            const certOperationMessage = document.getElementById('cert-operation-message');
            if (certOperationMessage) showMessage(certOperationMessage, 'Certificate download started', true);
        } catch (error) {
            console.error('Error downloading certificate:', error);
            const certOperationMessage = document.getElementById('cert-operation-message');
            if (certOperationMessage) showMessage(certOperationMessage, `Failed to download certificate: ${error.message}`, false);
        } finally {
            const downloadCertBtn = document.getElementById('download-cert-btn');
            if (downloadCertBtn) downloadCertBtn.disabled = false;
        }
    }
});

// Ensure the page initialization happens after DOM is fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize pages based on the current path
    const currentPath = window.location.pathname;
    
    if (currentPath.endsWith('/') || currentPath.endsWith('index.html') || currentPath.includes('/dashboard/') && !currentPath.includes('settings.html') && !currentPath.includes('logs.html')) {
        console.log("Initializing Dashboard Page");
        initDashboardPage();
    } else if (currentPath.includes('settings.html')) {
        initSettingsPage();
    } else if (currentPath.includes('logs.html')) {
        initLogsPage();
    }
});