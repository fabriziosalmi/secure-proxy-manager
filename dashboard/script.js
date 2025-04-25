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
    
    // Initialize
    fetchStatus();
    fetchConfig();
    
    // Refresh status every 10 seconds
    setInterval(fetchStatus, 10000);
    
    // Event listeners
    startBtn.addEventListener('click', () => controlSquid('start'));
    stopBtn.addEventListener('click', () => controlSquid('stop'));
    restartBtn.addEventListener('click', () => controlSquid('restart'));
    reloadBtn.addEventListener('click', () => controlSquid('reload'));
    updatePortBtn.addEventListener('click', updatePort);
    
    // Functions
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
    
    function setButtonsDisabled(disabled) {
        startBtn.disabled = disabled;
        stopBtn.disabled = disabled;
        restartBtn.disabled = disabled;
        reloadBtn.disabled = disabled;
    }
});