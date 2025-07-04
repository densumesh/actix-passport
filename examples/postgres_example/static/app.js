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
            body: JSON.stringify({ identifier: username, password })
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
            showMessage('Registration successful!', 'success');
            checkAuthStatus();
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
    document.getElementById('username-display').textContent = user.username || user.display_name || 'Anonymous';
    document.getElementById('user-id').textContent = user.id || 'N/A';
    document.getElementById('user-email').textContent = user.email || 'N/A';
    document.getElementById('user-display-name').textContent = user.display_name || 'N/A';

    // Display OAuth providers with badges
    const providersEl = document.getElementById('oauth-providers');
    if (user.oauth_providers && user.oauth_providers.length > 0) {
        providersEl.innerHTML = user.oauth_providers.map(provider =>
            `<span style="background: #007bff; color: white; padding: 2px 8px; border-radius: 12px; font-size: 12px; margin-right: 5px;">${provider}</span>`
        ).join('');
    } else {
        providersEl.textContent = 'Password authentication';
    }

    // Format creation date
    const createdEl = document.getElementById('user-created');
    if (user.created_at) {
        const date = new Date(user.created_at);
        createdEl.textContent = date.toLocaleDateString();
    } else {
        createdEl.textContent = 'N/A';
    }

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

// Check auth status when page loads
document.addEventListener('DOMContentLoaded', checkAuthStatus);
