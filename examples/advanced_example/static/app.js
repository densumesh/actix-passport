let currentToken = localStorage.getItem('bearer_token');

// Update UI based on authentication state
function updateAuthState() {
    const tokenDisplay = document.getElementById('token-display');
    const tokenElement = document.getElementById('current-token');
    
    if (currentToken) {
        tokenDisplay.style.display = 'block';
        tokenElement.textContent = currentToken;
    } else {
        tokenDisplay.style.display = 'none';
    }
}

// Show different sections
function showSection(sectionName) {
    // Hide all sections
    const sections = document.querySelectorAll('.auth-section');
    sections.forEach(section => section.classList.remove('active'));
    
    // Remove active class from all tabs
    const tabs = document.querySelectorAll('.nav-tab');
    tabs.forEach(tab => tab.classList.remove('active'));
    
    // Show selected section
    document.getElementById(`${sectionName}-section`).classList.add('active');
    
    // Add active class to clicked tab
    event.target.classList.add('active');
}

// Display response
function showResponse(data, isError = false) {
    const container = document.getElementById('response-container');
    const response = document.getElementById('response');
    
    container.style.display = 'block';
    response.className = `response ${isError ? 'error' : 'success'}`;
    response.textContent = JSON.stringify(data, null, 2);
    
    // Scroll to response
    container.scrollIntoView({ behavior: 'smooth' });
}

// Make API request
async function makeRequest(url, options = {}) {
    try {
        const response = await fetch(url, {
            headers: {
                'Content-Type': 'application/json',
                ...(currentToken && { 'Authorization': `Bearer ${currentToken}` }),
                ...options.headers
            },
            ...options
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showResponse(data, false);
            return data;
        } else {
            showResponse(data, true);
            return null;
        }
    } catch (error) {
        showResponse({ error: 'Network Error', message: error.message }, true);
        return null;
    }
}

// Register user
document.getElementById('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const email = document.getElementById('reg-email').value;
    const username = document.getElementById('reg-username').value;
    const password = document.getElementById('reg-password').value;
    const displayName = document.getElementById('reg-display-name').value;
    
    if (!email && !username) {
        showResponse({ error: 'Validation Error', message: 'Either email or username is required' }, true);
        return;
    }
    
    if (!password || password.length < 8) {
        showResponse({ error: 'Validation Error', message: 'Password must be at least 8 characters long' }, true);
        return;
    }
    
    const payload = {
        password,
        ...(email && { email }),
        ...(username && { username }),
        ...(displayName && { display_name: displayName })
    };
    
    const result = await makeRequest('/auth/register', {
        method: 'POST',
        body: JSON.stringify(payload)
    });
    
    if (result && result.token) {
        currentToken = result.token;
        localStorage.setItem('bearer_token', currentToken);
        updateAuthState();
        
        // Show success message
        showResponse({
            message: 'Registration successful!',
            user: result.user,
            token: result.token
        }, false);
        
        // Switch to profile tab
        setTimeout(() => {
            showSection('profile');
        }, 2000);
    }
});

// Login user
document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const identifier = document.getElementById('login-identifier').value;
    const password = document.getElementById('login-password').value;
    
    if (!identifier || !password) {
        showResponse({ error: 'Validation Error', message: 'Both identifier and password are required' }, true);
        return;
    }
    
    const result = await makeRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ identifier, password })
    });
    
    if (result && result.token) {
        currentToken = result.token;
        localStorage.setItem('bearer_token', currentToken);
        updateAuthState();
        
        // Show success message
        showResponse({
            message: 'Login successful!',
            user: result.user,
            token: result.token
        }, false);
        
        // Switch to profile tab
        setTimeout(() => {
            showSection('profile');
        }, 2000);
    }
});

// Get user profile
async function getProfile() {
    if (!currentToken) {
        showResponse({ error: 'Authentication Required', message: 'Please login first to get a Bearer token' }, true);
        return;
    }
    
    await makeRequest('/auth/profile', {
        method: 'GET'
    });
}

// Logout user
async function logout() {
    if (!currentToken) {
        showResponse({ error: 'Not Authenticated', message: 'No active session to logout' }, true);
        return;
    }
    
    const result = await makeRequest('/auth/logout', {
        method: 'POST'
    });
    
    if (result) {
        currentToken = null;
        localStorage.removeItem('bearer_token');
        updateAuthState();
        
        showResponse({ message: 'Logged out successfully' }, false);
    }
}

// Test API connectivity
async function testConnection() {
    try {
        const response = await fetch('/health');
        const data = await response.json();
        console.log('API Health Check:', data);
    } catch (error) {
        console.error('API connection failed:', error);
    }
}

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    updateAuthState();
    testConnection();
    
    // Load API info
    fetch('/api/info')
        .then(response => response.json())
        .then(data => {
            console.log('API Documentation:', data);
        })
        .catch(error => {
            console.error('Failed to load API info:', error);
        });
});

// Add some helper functions for demonstration
function clearAll() {
    currentToken = null;
    localStorage.removeItem('bearer_token');
    updateAuthState();
    document.getElementById('response-container').style.display = 'none';
    
    // Clear all form fields
    document.querySelectorAll('input').forEach(input => input.value = '');
    
    showResponse({ message: 'All data cleared' }, false);
}

function copyToken() {
    if (currentToken) {
        navigator.clipboard.writeText(currentToken).then(() => {
            alert('Token copied to clipboard!');
        }).catch(err => {
            console.error('Failed to copy token:', err);
        });
    }
}

// Add copy button functionality
document.addEventListener('DOMContentLoaded', () => {
    const tokenInfo = document.querySelector('.token-info');
    if (tokenInfo) {
        const copyButton = document.createElement('button');
        copyButton.textContent = 'Copy Token';
        copyButton.onclick = copyToken;
        copyButton.style.marginTop = '10px';
        copyButton.style.fontSize = '12px';
        copyButton.style.padding = '5px 10px';
        tokenInfo.appendChild(copyButton);
        
        const clearButton = document.createElement('button');
        clearButton.textContent = 'Clear All';
        clearButton.onclick = clearAll;
        clearButton.style.marginTop = '10px';
        clearButton.style.marginLeft = '10px';
        clearButton.style.fontSize = '12px';
        clearButton.style.padding = '5px 10px';
        clearButton.style.backgroundColor = '#dc3545';
        tokenInfo.appendChild(clearButton);
    }
});