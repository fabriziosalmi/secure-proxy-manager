/**
 * First-time user guidance functionality
 * Provides a guided tour of the interface for new users
 */

$(document).ready(function() {
    // Check if user has seen the guidance before
    const hasSeenGuidance = localStorage.getItem('hasSeenGuidance');
    
    if (!hasSeenGuidance) {
        // Show welcome modal on first visit
        setTimeout(function() {
            $('#welcomeModal').modal('show');
        }, 1000);
    }
    
    // Mark guidance as seen when user clicks "Don't show again"
    $('#dontShowAgain').change(function() {
        if ($(this).is(':checked')) {
            localStorage.setItem('hasSeenGuidance', 'true');
        } else {
            localStorage.removeItem('hasSeenGuidance');
        }
    });
    
    // Handle tour buttons
    $('#startTour').click(function() {
        $('#welcomeModal').modal('hide');
        startGuidedTour();
    });
    
    // Add handler for the "Start Guided Tour" menu item
    $('#start-guided-tour').click(function(e) {
        e.preventDefault();
        startGuidedTour();
    });
    
    // Reset guided tour (for testing)
    $('#resetGuidance').click(function() {
        localStorage.removeItem('hasSeenGuidance');
        showToast('Guidance reset. Refresh the page to see the welcome message.', 'info');
    });
});

function startGuidedTour() {
    // Show the tour indicator
    $('#tour-indicator').fadeIn();
    
    // Handle exit tour button click
    $('#end-tour-btn').off('click').on('click', function() {
        endTour();
        showToast('Tour ended. You can restart it anytime from the Help menu.', 'info');
    });
    
    // Define tour steps
    const tourSteps = [
        {
            element: '.navbar-brand',
            title: 'Welcome to Secure Proxy',
            content: 'This is your secure proxy management interface. Click here anytime to return to the dashboard.',
            placement: 'bottom'
        },
        {
            element: 'a[href="/"]',
            title: 'Dashboard',
            content: 'This is your main dashboard where you can monitor proxy status and performance.',
            placement: 'right'
        },
        {
            element: 'a[href="/blacklists"]',
            title: 'Blacklists',
            content: 'Manage blocked IP addresses and domains to enhance security.',
            placement: 'right'
        },
        {
            element: 'a[href="/logs"]',
            title: 'Logs',
            content: 'Review access logs and monitor traffic through your proxy.',
            placement: 'right'
        },
        {
            element: 'a[href="/settings"]',
            title: 'Settings',
            content: 'Configure your proxy settings and security options.',
            placement: 'right'
        },
        {
            element: '#navbarDropdown',
            title: 'Help & Resources',
            content: 'Access documentation, keyboard shortcuts, and information about the application.',
            placement: 'left'
        }
    ];
    
    // Initialize the tour if Bootstrap Popper is available
    if (typeof bootstrap !== 'undefined' && bootstrap.Popover) {
        let currentStep = 0;
        showTourStep(currentStep, tourSteps);
        
        // Handle "Next" button click
        $(document).on('click', '.tour-next', function() {
            currentStep++;
            if (currentStep < tourSteps.length) {
                showTourStep(currentStep, tourSteps);
            } else {
                endTour();
                showToast('Tour completed! Explore the interface at your own pace.', 'success');
            }
        });
        
        // Handle "Previous" button click
        $(document).on('click', '.tour-prev', function() {
            if (currentStep > 0) {
                currentStep--;
                showTourStep(currentStep, tourSteps);
            }
        });
        
        // Handle "Skip" button click
        $(document).on('click', '.tour-skip', function() {
            endTour();
            showToast('Tour skipped. You can access help anytime from the menu.', 'info');
        });
    } else {
        showToast('Tour functionality not available. Please upgrade your browser.', 'warning');
    }
}

function showTourStep(stepIndex, steps) {
    // Clean up any existing tour popover
    endTour();
    
    // Create a new popover for the current step
    const step = steps[stepIndex];
    const $element = $(step.element);
    
    if ($element.length === 0) {
        console.error(`Element not found: ${step.element}`);
        return;
    }
    
    // Highlight the element with a pulse effect
    $element.addClass('tour-highlight');
    
    // Create navigation buttons
    const isFirst = stepIndex === 0;
    const isLast = stepIndex === steps.length - 1;
    const prevButton = !isFirst ? 
        '<button class="btn btn-sm btn-outline-secondary tour-prev">Previous</button>' : '';
    const nextButton = !isLast ? 
        '<button class="btn btn-sm btn-primary tour-next">Next</button>' : 
        '<button class="btn btn-sm btn-success tour-next">Finish</button>';
    
    // Create popover content
    const content = `
        <div class="tour-content">
            <p>${step.content}</p>
            <div class="d-flex justify-content-between align-items-center mt-3">
                <div>
                    ${prevButton}
                    <button class="btn btn-sm btn-link text-muted tour-skip">Skip Tour</button>
                </div>
                <div>
                    <span class="badge bg-light text-dark me-2">${stepIndex + 1}/${steps.length}</span>
                    ${nextButton}
                </div>
            </div>
        </div>
    `;
    
    try {
        // Create and show the popover
        const popover = new bootstrap.Popover($element[0], {
            title: step.title,
            content: content,
            placement: step.placement,
            html: true,
            trigger: 'manual',
            customClass: 'tour-popover',
            container: 'body'
        });
        
        popover.show();
    } catch (e) {
        console.error('Error showing popover:', e);
        // Fallback method
        $element.attr('data-bs-toggle', 'popover')
               .attr('data-bs-placement', step.placement)
               .attr('data-bs-title', step.title)
               .attr('data-bs-content', content)
               .attr('data-bs-html', 'true')
               .attr('data-bs-custom-class', 'tour-popover');
        
        new bootstrap.Popover($element[0]).show();
    }
    
    // Scroll to the element if needed
    $('html, body').animate({
        scrollTop: $element.offset().top - 100
    }, 300);
}

function endTour() {
    // Hide the tour indicator
    $('#tour-indicator').fadeOut();
    
    // Hide any active popovers
    $('.tour-highlight').each(function() {
        if (this._tippy) {
            this._tippy.destroy();
        } else {
            const popover = bootstrap.Popover.getInstance(this);
            if (popover) {
                popover.dispose();
            }
        }
    });
    
    // Remove highlight classes
    $('.tour-highlight').removeClass('tour-highlight');
}
