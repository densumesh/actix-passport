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
    }, 8000);
}

// Handle login form submission
document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const formData = new FormData(e.target);
    const identifier = formData.get('username');
    const password = formData.get('password');

    let username;
    let email;

    if (identifier.includes('@')) {
        email = identifier;
    } else {
        username = identifier;
    }

    try {
        const response = await fetch('/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, username, password })
        });

        if (response.ok) {
            showMessage('Login successful!', 'success');
            checkAuthStatus();
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
            showMessage('Registration successful! Please check your email for verification.', 'success');
            // Switch to verify tab
            document.querySelector('.tablinks[onclick*="verify"]').click();
        } else {
            const error = await response.text();
            showMessage(`Registration failed: ${error}`, 'error');
        }
    } catch (error) {
        showMessage(`Registration error: ${error.message}`, 'error');
    }
});

// Handle email verification form submission
document.getElementById('verify-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const formData = new FormData(e.target);
    const token = formData.get('token');

    try {
        const response = await fetch('/auth/verify-email', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ token })
        });

        if (response.ok) {
            showMessage('Email verified successfully!', 'success');
            document.getElementById('verify-form').reset();
            // Switch back to login tab
            document.querySelector('.tablinks[onclick*="login"]').click();
        } else {
            const error = await response.text();
            showMessage(`Email verification failed: ${error}`, 'error');
        }
    } catch (error) {
        showMessage(`Email verification error: ${error.message}`, 'error');
    }
});

// Handle forgot password form submission
document.getElementById('forgot-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const formData = new FormData(e.target);
    const email = formData.get('email');

    try {
        const response = await fetch('/auth/forgot-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email })
        });

        if (response.ok) {
            showMessage('If an account with this email exists, a password reset link has been sent.', 'info');
            document.getElementById('forgot-form').reset();
            // Switch to reset tab
            document.querySelector('.tablinks[onclick*="reset"]').click();
        } else {
            const error = await response.text();
            showMessage(`Password reset request failed: ${error}`, 'error');
        }
    } catch (error) {
        showMessage(`Password reset error: ${error.message}`, 'error');
    }
});

// Handle password reset form submission
document.getElementById('reset-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const formData = new FormData(e.target);
    const token = formData.get('token');
    const password = formData.get('password');

    try {
        const response = await fetch('/auth/reset-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ token, new_password: password })
        });

        if (response.ok) {
            showMessage('Password reset successfully! You can now log in with your new password.', 'success');
            document.getElementById('reset-form').reset();
            // Switch back to login tab
            document.querySelector('.tablinks[onclick*="login"]').click();
        } else {
            const error = await response.text();
            showMessage(`Password reset failed: ${error}`, 'error');
        }
    } catch (error) {
        showMessage(`Password reset error: ${error.message}`, 'error');
    }
});

// Show user section after successful authentication
function showUserSection(user) {
    document.getElementById('auth-section').style.display = 'none';
    document.getElementById('user-section').style.display = 'block';

    // Update user info
    document.getElementById('username-display').textContent = user.username || user.display_name || 'Anonymous';
    document.getElementById('user-id').textContent = user.id || 'N/A';
    document.getElementById('user-email').textContent = user.email || 'N/A';
    document.getElementById('user-display-name').textContent = user.display_name || 'N/A';

    // Display email verification status
    const emailStatusEl = document.getElementById('email-status');
    if (user.is_email_verified) {
        emailStatusEl.innerHTML = '<span class="verification-status verified">✓ Verified</span>';
    } else {
        emailStatusEl.innerHTML = '<span class="verification-status unverified">✗ Not Verified</span>';
    }

    // Display OAuth providers with badges
    const providersEl = document.getElementById('oauth-providers');
    if (user.oauth_providers && user.oauth_providers.length > 0) {
        providersEl.innerHTML = user.oauth_providers.map(provider =>
            `<span style="background: #007bff; color: white; padding: 2px 8px; border-radius: 12px; font-size: 12px; margin-right: 5px;">${provider}</span>`
        ).join('');
    } else {
        providersEl.textContent = 'Email + Password authentication';
    }

    // Format creation date
    const createdEl = document.getElementById('user-created');
    if (user.created_at) {
        const date = new Date(user.created_at);
        createdEl.textContent = date.toLocaleDateString();
    } else {
        createdEl.textContent = 'N/A';
    }

    // Clear all forms
    document.getElementById('login-form').reset();
    document.getElementById('register-form').reset();
    document.getElementById('verify-form').reset();
    document.getElementById('forgot-form').reset();
    document.getElementById('reset-form').reset();
}

// Show auth section (login/register forms)
function showAuthSection() {
    document.getElementById('auth-section').style.display = 'block';
    document.getElementById('user-section').style.display = 'none';
    // Switch to login tab
    document.querySelector('.tablinks[onclick*="login"]').click();
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

// Check if user is already authenticated on page load
async function checkAuthStatus() {
    try {
        const response = await fetch('/api/user');
        if (response.ok) {
            const data = await response.json();
            showUserSection(data.user);
        }
    } catch (error) {
        // User not authenticated, stay on auth page
        console.log('User not authenticated');
    }
}

// Check auth status when page loads
document.addEventListener('DOMContentLoaded', () => {
    checkAuthStatus();

    // Check for error parameters in URL
    const urlParams = new URLSearchParams(window.location.search);
    const error = urlParams.get('error');
    if (error === 'invalid_verification_token') {
        showMessage('Invalid or expired verification token. Please request a new verification email.', 'error');
    }
});