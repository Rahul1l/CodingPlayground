// Coding Playground - Client-side JavaScript

// Set current year
document.getElementById('year') && (document.getElementById('year').textContent = new Date().getFullYear());

// Utility functions
function showAlert(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert ${type}`;
    alertDiv.textContent = message;
    
    // Insert at the top of the page
    const container = document.querySelector('.container');
    if (container) {
        container.insertBefore(alertDiv, container.firstChild);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            alertDiv.remove();
        }, 5000);
    }
}

function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    const toggle = document.querySelector(`[onclick="togglePassword('${inputId}')"]`);
    
    if (input.type === 'password') {
        input.type = 'text';
        toggle.textContent = 'Hide';
    } else {
        input.type = 'password';
        toggle.textContent = 'Show';
    }
}

// Form validation
function validateForm(formId) {
    const form = document.getElementById(formId);
    if (!form) return false;
    
    const requiredFields = form.querySelectorAll('[required]');
    let isValid = true;
    
    requiredFields.forEach(field => {
        if (!field.value.trim()) {
            field.style.borderColor = '#dc2626';
            isValid = false;
        } else {
            field.style.borderColor = '#334155';
        }
    });
    
    return isValid;
}

// AJAX helper
async function makeRequest(url, options = {}) {
    try {
        const response = await fetch(url, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('Request failed:', error);
        showAlert(`Network error: ${error.message}`, 'danger');
        throw error;
    }
}

// Delete confirmation
function confirmDelete(itemType, itemName) {
    return confirm(`Are you sure you want to delete this ${itemType}?\n\n${itemName}\n\nThis action cannot be undone.`);
}

// Countdown timer
function startCountdown(targetTime, elementId) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    function updateCountdown() {
        const now = new Date().getTime();
        const target = new Date(targetTime).getTime();
        const distance = target - now;
        
        if (distance < 0) {
            element.innerHTML = "Time's up!";
            return;
        }
        
        const days = Math.floor(distance / (1000 * 60 * 60 * 24));
        const hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((distance % (1000 * 60)) / 1000);
        
        let countdownText = "";
        if (days > 0) countdownText += days + "d ";
        if (hours > 0) countdownText += hours + "h ";
        if (minutes > 0) countdownText += minutes + "m ";
        countdownText += seconds + "s";
        
        element.innerHTML = countdownText;
    }
    
    updateCountdown();
    setInterval(updateCountdown, 1000);
}

// Code execution
async function executeCode(code, outputElementId) {
    const outputElement = document.getElementById(outputElementId);
    if (!outputElement) return;
    
    outputElement.textContent = "Running code...";
    outputElement.className = "output-area";
    
    try {
        const response = await makeRequest('/compiler/execute', {
            method: 'POST',
            body: JSON.stringify({ code: code })
        });
        
        if (response.success) {
            outputElement.textContent = response.output || "No output";
            outputElement.className = "output-area";
        } else {
            outputElement.textContent = `Error: ${response.error}`;
            outputElement.className = "output-area alert";
        }
    } catch (error) {
        outputElement.textContent = `Execution failed: ${error.message}`;
        outputElement.className = "output-area alert";
    }
}

// Question code execution
async function executeQuestionCode(questionId, code, outputElementId) {
    const outputElement = document.getElementById(outputElementId);
    if (!outputElement) return;
    
    outputElement.textContent = "Running code...";
    outputElement.className = "output-area";
    
    try {
        const response = await makeRequest('/question/execute', {
            method: 'POST',
            body: JSON.stringify({ 
                question_id: questionId,
                code: code 
            })
        });
        
        if (response.success) {
            outputElement.textContent = response.output || "No output";
            outputElement.className = "output-area";
            
            if (response.validation) {
                const validationDiv = document.createElement('div');
                validationDiv.className = 'alert info';
                validationDiv.innerHTML = `<strong>AI Validation:</strong><br>${response.validation}`;
                outputElement.parentNode.appendChild(validationDiv);
            }
        } else {
            outputElement.textContent = `Error: ${response.error}`;
            outputElement.className = "output-area alert";
        }
    } catch (error) {
        outputElement.textContent = `Execution failed: ${error.message}`;
        outputElement.className = "output-area alert";
    }
}

// Admin question code execution
async function executeAdminQuestionCode(questionId, code, outputElementId) {
    const outputElement = document.getElementById(outputElementId);
    if (!outputElement) return;
    
    outputElement.textContent = "Running code...";
    outputElement.className = "output-area";
    
    try {
        const response = await makeRequest('/admin/question/execute', {
            method: 'POST',
            body: JSON.stringify({ 
                question_id: questionId,
                code: code 
            })
        });
        
        if (response.success) {
            outputElement.textContent = response.output || "No output";
            outputElement.className = "output-area";
            
            if (response.validation) {
                const validationDiv = document.createElement('div');
                validationDiv.className = 'alert info';
                validationDiv.innerHTML = `<strong>AI Validation:</strong><br>${response.validation}`;
                outputElement.parentNode.appendChild(validationDiv);
            }
        } else {
            outputElement.textContent = `Error: ${response.error}`;
            outputElement.className = "output-area alert";
        }
    } catch (error) {
        outputElement.textContent = `Execution failed: ${error.message}`;
        outputElement.className = "output-area alert";
    }
}

// Clear output
function clearOutput(outputElementId) {
    const outputElement = document.getElementById(outputElementId);
    if (outputElement) {
        outputElement.textContent = "";
        outputElement.className = "output-area";
    }
}

// Test restrictions (disable copy/paste, right-click, etc.)
function enableTestRestrictions() {
    // Disable right-click
    document.addEventListener('contextmenu', e => e.preventDefault());
    
    // Disable copy/paste
    document.addEventListener('copy', e => e.preventDefault());
    document.addEventListener('paste', e => e.preventDefault());
    document.addEventListener('cut', e => e.preventDefault());
    
    // Disable F12, Ctrl+Shift+I, etc.
    document.addEventListener('keydown', e => {
        if (e.key === 'F12' || 
            (e.ctrlKey && e.shiftKey && e.key === 'I') ||
            (e.ctrlKey && e.shiftKey && e.key === 'C') ||
            (e.ctrlKey && e.key === 'U')) {
            e.preventDefault();
        }
    });
    
    // Disable text selection
    document.addEventListener('selectstart', e => e.preventDefault());
}

// Initialize test restrictions if on test page
if (window.location.pathname.includes('/test/start')) {
    enableTestRestrictions();
}

// Auto-save form data
function autoSaveForm(formId) {
    const form = document.getElementById(formId);
    if (!form) return;
    
    const inputs = form.querySelectorAll('input, textarea, select');
    
    inputs.forEach(input => {
        // Load saved data
        const saved = localStorage.getItem(`form_${formId}_${input.name}`);
        if (saved) {
            input.value = saved;
        }
        
        // Save on change
        input.addEventListener('input', () => {
            localStorage.setItem(`form_${formId}_${input.name}`, input.value);
        });
    });
}

// Clear auto-saved data
function clearAutoSave(formId) {
    const form = document.getElementById(formId);
    if (!form) return;
    
    const inputs = form.querySelectorAll('input, textarea, select');
    inputs.forEach(input => {
        localStorage.removeItem(`form_${formId}_${input.name}`);
    });
}

// Initialize auto-save for forms
document.addEventListener('DOMContentLoaded', () => {
    const forms = document.querySelectorAll('form[id]');
    forms.forEach(form => autoSaveForm(form.id));
});

// Export functions to global scope for HTML onclick handlers
window.togglePassword = togglePassword;
window.executeCode = executeCode;
window.executeQuestionCode = executeQuestionCode;
window.executeAdminQuestionCode = executeAdminQuestionCode;
window.clearOutput = clearOutput;
window.confirmDelete = confirmDelete;
window.startCountdown = startCountdown;
window.showAlert = showAlert;