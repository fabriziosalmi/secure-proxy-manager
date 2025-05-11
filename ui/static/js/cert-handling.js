// Certificate handling functions
$(document).ready(function() {
    // HTTPS filtering toggle - extend existing behavior
    $('#enable_https_filtering').change(function() {
        if ($(this).is(':checked')) {
            // When HTTPS filtering is enabled, load certificate content
            loadCertificateContent();
        }
    });
    
    // Load certificate content
    function loadCertificateContent() {
        $.ajax({
            url: '/api/maintenance/view-cert',
            method: 'GET',
            dataType: 'json',
            success: function(response) {
                if (response.status === 'success' && response.data && response.data.certificate) {
                    $('#cert-content').text(response.data.certificate);
                } else {
                    $('#cert-content').text('Could not load certificate: ' + 
                        (response.message || 'Unknown error'));
                }
            },
            error: function(xhr, status, error) {
                let errorMessage = 'Could not load certificate';
                try {
                    const response = JSON.parse(xhr.responseText);
                    errorMessage = response.message || errorMessage;
                } catch (e) {
                    // Use default error message
                }
                $('#cert-content').text(errorMessage);
            }
        });
    }
    
    // Copy certificate button
    $('#copy-cert-btn').click(function() {
        const certContent = $('#cert-content').text();
        navigator.clipboard.writeText(certContent).then(function() {
            showToast('Certificate copied to clipboard', 'success');
        }, function() {
            showToast('Failed to copy certificate', 'error');
        });
    });
    
    // Download CA Certificate button - override the default behavior
    $('#download-cert-btn').off('click').on('click', function(e) {
        e.preventDefault();
        
        // Create a temporary link element for proper download
        const link = document.createElement('a');
        link.href = '/api/maintenance/download-cert';
        link.download = 'secure-proxy-ca.pem'; // Suggest a filename
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    });
    
    // If HTTPS filtering is enabled on page load, load certificate
    if ($('#enable_https_filtering').is(':checked')) {
        loadCertificateContent();
    }
});
