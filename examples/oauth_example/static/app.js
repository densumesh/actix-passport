// Tab switching functionality
function openTab(evt, tabName) {
    var i, tabcontent, tablinks;
    tabcontent = document.getElementsByClassName("tab-content");
    for (i = 0; i < tabcontent.length; i++) {
        tabcontent[i].classList.remove("active");
    }
    tablinks = document.getElementsByClassName("tablinks");
    for (i = 0; i < tablinks.length; i++) {
        tablinks[i].classList.remove("active");
    }
    document.getElementById(tabName).classList.add("active");
    evt.currentTarget.classList.add("active");
}

// Show message to user
function showMessage(message, type = 'error') {
    const messageEl = document.getElementById('message');
    messageEl.innerHTML = `<div class="message ${type}">${message}</div>`;
    setTimeout(() => {
        messageEl.innerHTML = '';
    }, 5000);
}

// Handle login form submission
document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const username = formData.get('username');
    const password = formData.get('password');
    
    try {
        const response = await fetch('/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password })
        });
        
        if (response.ok) {
            const data = await response.json();
            showMessage('Login successful!', 'success');
            showUserSection(data.user);
        } else {
            const error = await response.text();
            showMessage(`Login failed: ${error}`, 'error');
        }
    } catch (error) {
        showMessage(`Login error: ${error.message}`, 'error');
    }
});

// Handle register form submission
document.getElementById('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const username = formData.get('username');
    const email = formData.get('email');
    const password = formData.get('password');
    
    try {
        const response = await fetch('/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, email, password })
        });
        
        if (response.ok) {
            const data = await response.json();
            showMessage('Registration successful!', 'success');
            showUserSection(data.user);
        } else {
            const error = await response.text();
            showMessage(`Registration failed: ${error}`, 'error');
        }
    } catch (error) {
        showMessage(`Registration error: ${error.message}`, 'error');
    }
});

// Show user section after successful authentication
function showUserSection(user) {
    document.getElementById('auth-section').style.display = 'none';
    document.getElementById('user-section').style.display = 'block';
    
    // Update user info
    document.getElementById('username-display').textContent = user.username || 'Anonymous';
    document.getElementById('user-id').textContent = user.id || 'N/A';
    document.getElementById('user-email').textContent = user.email || 'N/A';
    
    // Clear forms
    document.getElementById('login-form').reset();
    document.getElementById('register-form').reset();
}

// Show auth section (login/register forms)
function showAuthSection() {
    document.getElementById('auth-section').style.display = 'block';
    document.getElementById('user-section').style.display = 'none';
}

// Handle logout
async function logout() {
    try {
        const response = await fetch('/auth/logout', {
            method: 'POST',
        });
        
        if (response.ok) {
            showMessage('Logged out successfully!', 'success');
            showAuthSection();
        } else {
            showMessage('Logout failed', 'error');
        }
    } catch (error) {
        showMessage(`Logout error: ${error.message}`, 'error');
    }
}

// Generate OAuth URL with redirect parameter
function getOAuthUrl(provider) {
    // Redirect to main page after OAuth success
    const redirectUrl = encodeURIComponent('/');
    return `/auth/${provider}?redirect_url=${redirectUrl}`;
}

// Update OAuth button URLs with redirect parameters
function updateOAuthButtons() {
    const googleBtn = document.querySelector('.oauth-btn.google');
    const githubBtn = document.querySelector('.oauth-btn.github');
    
    if (googleBtn) {
        googleBtn.href = getOAuthUrl('google');
    }
    if (githubBtn) {
        githubBtn.href = getOAuthUrl('github');
    }
}

// Check if user is already authenticated on page load
async function checkAuthStatus() {
    try {
        const response = await fetch('/api/user');
        if (response.ok) {
            const data = await response.json();
            showUserSection(data.user);
        }
    } catch (error) {
        // User not authenticated, stay on login page
        console.log('User not authenticated');
    }
}

// Handle OAuth callback errors (successful OAuth redirects server-side)
function handleOAuthCallback() {
    const urlParams = new URLSearchParams(window.location.search);
    const error = urlParams.get('error');
    
    if (error) {
        showMessage(`OAuth error: ${error}`, 'error');
        // Clean up URL
        window.history.replaceState({}, document.title, window.location.pathname);
    }
}

// Initialize page when DOM loads
document.addEventListener('DOMContentLoaded', () => {
    updateOAuthButtons();
    handleOAuthCallback();
    checkAuthStatus();
});