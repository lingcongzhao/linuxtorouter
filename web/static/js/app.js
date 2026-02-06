// Linux Router GUI - JavaScript utilities

// Auto-dismiss alerts after 5 seconds
document.addEventListener('htmx:afterSwap', function(event) {
    const alerts = event.detail.target.querySelectorAll('#alert-box');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            alert.style.transition = 'opacity 300ms ease-out';
            alert.style.opacity = '0';
            setTimeout(function() {
                alert.remove();
            }, 300);
        }, 5000);
    });
});

// Confirm dangerous actions
document.addEventListener('htmx:confirm', function(event) {
    if (event.detail.elt.hasAttribute('data-confirm')) {
        event.preventDefault();
        if (confirm(event.detail.elt.getAttribute('data-confirm'))) {
            event.detail.issueRequest();
        }
    }
});

// Handle form validation
document.addEventListener('submit', function(event) {
    const form = event.target;
    if (!form.checkValidity()) {
        event.preventDefault();
        form.reportValidity();
    }
});

// Toggle mobile menu
function toggleMobileMenu() {
    const menu = document.getElementById('mobile-menu');
    if (menu) {
        menu.classList.toggle('hidden');
    }
}

// Copy to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(function() {
        showToast('Copied to clipboard');
    }).catch(function(err) {
        console.error('Failed to copy: ', err);
    });
}

// Show toast notification
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `fixed bottom-4 right-4 px-4 py-2 rounded-md text-white text-sm font-medium shadow-lg z-50 ${
        type === 'error' ? 'bg-red-600' :
        type === 'success' ? 'bg-green-600' :
        'bg-gray-800'
    }`;
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(function() {
        toast.style.transition = 'opacity 300ms ease-out';
        toast.style.opacity = '0';
        setTimeout(function() {
            toast.remove();
        }, 300);
    }, 3000);
}

// Format bytes to human readable
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Periodic refresh for stats (when element is present)
document.addEventListener('DOMContentLoaded', function() {
    const statsContainer = document.getElementById('stats-container');
    if (statsContainer && statsContainer.hasAttribute('hx-get')) {
        // HTMX will handle the polling via hx-trigger
    }
});

// Handle keyboard shortcuts
document.addEventListener('keydown', function(event) {
    // Escape to close modals
    if (event.key === 'Escape') {
        const modals = document.querySelectorAll('[role="dialog"]');
        modals.forEach(function(modal) {
            const closeBtn = modal.querySelector('[data-close-modal]');
            if (closeBtn) {
                closeBtn.click();
            }
        });
    }
});

// HTMX extension for handling redirects
document.addEventListener('htmx:beforeSwap', function(event) {
    // If server sends HX-Redirect, let HTMX handle it
    if (event.detail.xhr.getResponseHeader('HX-Redirect')) {
        return;
    }
});

// Loading state management
document.addEventListener('htmx:beforeRequest', function(event) {
    const target = event.detail.elt;
    if (target.tagName === 'BUTTON') {
        target.disabled = true;
        target.setAttribute('data-original-text', target.innerHTML);
        target.innerHTML = '<svg class="animate-spin h-4 w-4 mr-2 inline" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>Loading...';
    }
});

document.addEventListener('htmx:afterRequest', function(event) {
    const target = event.detail.elt;
    if (target.tagName === 'BUTTON' && target.hasAttribute('data-original-text')) {
        target.disabled = false;
        target.innerHTML = target.getAttribute('data-original-text');
        target.removeAttribute('data-original-text');
    }
});
