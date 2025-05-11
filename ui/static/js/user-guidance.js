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
    
    // Add CSS for step dots if not already added
    if (!$('#tour-dot-styles').length) {
        $('head').append(`
            <style id="tour-dot-styles">
                .step-counter-container {
                    display: flex;
                    align-items: center;
                    gap: 5px;
                }
                
                .step-dot {
                    width: 8px;
                    height: 8px;
                    border-radius: 50%;
                    background-color: rgba(0, 0, 0, 0.2);
                    cursor: pointer;
                    transition: all 0.2s ease;
                    display: inline-block;
                }
                
                [data-bs-theme="dark"] .step-dot {
                    background-color: rgba(255, 255, 255, 0.2);
                }
                
                .step-dot.active {
                    background-color: var(--primary-color, #3a86ff);
                    transform: scale(1.3);
                }
                
                .step-dot:hover {
                    transform: scale(1.2);
                    background-color: var(--primary-hover, #2667cc);
                }
            </style>
        `);
    }
    
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
        
        // Handle "Next" button click from popover
        $(document).on('click', '.tour-next', function() {
            currentStep++;
            if (currentStep < tourSteps.length) {
                showTourStep(currentStep, tourSteps);
            } else {
                endTour();
                showToast('Tour completed! Explore the interface at your own pace.', 'success');
            }
        });
        
        // Handle "Previous" button click from popover
        $(document).on('click', '.tour-prev', function() {
            if (currentStep > 0) {
                currentStep--;
                showTourStep(currentStep, tourSteps);
            }
        });
        
        // Handle "Skip" button click from popover
        $(document).on('click', '.tour-skip', function() {
            endTour();
            showToast('Tour skipped. You can access help anytime from the menu.', 'info');
        });
        
        // Handle next button click from tour indicator
        $('#next-tour-step').off('click').on('click', function() {
            currentStep++;
            if (currentStep < tourSteps.length) {
                showTourStep(currentStep, tourSteps);
            } else {
                endTour();
                showToast('Tour completed! Explore the interface at your own pace.', 'success');
            }
        });
        
        // Handle previous button click from tour indicator
        $('#prev-tour-step').off('click').on('click', function() {
            if (currentStep > 0) {
                currentStep--;
                showTourStep(currentStep, tourSteps);
            }
        });
        
        // Handle exit tour button click
        $('#end-tour-btn').off('click').on('click', function() {
            endTour();
            showToast('Tour ended. You can restart it anytime from the Help menu.', 'info');
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
                <div class="d-flex align-items-center">
                    <div class="step-counter-container me-2">
                        ${Array.from({length: steps.length}, (_, i) => 
                            `<span class="step-dot ${i === stepIndex ? 'active' : ''}" data-step="${i}"></span>`
                        ).join('')}
                    </div>
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
        
        // Add click handlers for the step dots
        $('.step-dot').click(function() {
            const targetStep = parseInt($(this).data('step'));
            showTourStep(targetStep, steps);
        });
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
