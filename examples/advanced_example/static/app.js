// Bearer token storage
let currentToken = localStorage.getItem('bearer_token');

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
}

// Make authenticated API request
async function makeAuthenticatedRequest(url, options = {}) {
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };

    if (currentToken) {
        headers['Authorization'] = `Bearer ${currentToken}`;
    }

    return fetch(url, {
        ...options,
        headers
    });
}

// Handle login form submission
document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const formData = new FormData(e.target);
    const identifier = formData.get('identifier');
    const password = formData.get('password');

    try {
        const response = await fetch('/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ identifier, password })
        });

        if (response.ok) {
            const data = await response.json();
            currentToken = data.token;
            localStorage.setItem('bearer_token', currentToken);
            showMessage('Login successful!', 'success');
            showUserSection(data.user);
        } else {
            const error = await response.json();
            showMessage(`Login failed: ${error.message}`, 'error');
        }
    } catch (error) {
        showMessage(`Login error: ${error.message}`, 'error');
    }
});

// Handle register form submission
document.getElementById('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const formData = new FormData(e.target);
    const email = formData.get('email');
    const username = formData.get('username');
    const password = formData.get('password');
    const display_name = formData.get('display_name');

    const payload = { password };
    if (email) payload.email = email;
    if (username) payload.username = username;
    if (display_name) payload.display_name = display_name;

    try {
        const response = await fetch('/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            const data = await response.json();
            currentToken = data.token;
            localStorage.setItem('bearer_token', currentToken);
            showMessage('Registration successful!', 'success');
            showUserSection(data.user);
        } else {
            const error = await response.json();
            showMessage(`Registration failed: ${error.message}`, 'error');
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
    document.getElementById('username-display').textContent = user.username || user.display_name || user.email || 'User';
    document.getElementById('user-id').textContent = user.id || 'N/A';
    document.getElementById('user-email').textContent = user.email || 'N/A';
    document.getElementById('user-username').textContent = user.username || 'N/A';
    document.getElementById('user-display-name').textContent = user.display_name || 'N/A';

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

// Handle profile button click
document.getElementById('get-profile-btn').addEventListener('click', async () => {
    if (!currentToken) {
        showMessage('Please login first to get a token', 'error');
        return;
    }

    try {
        const response = await makeAuthenticatedRequest('/auth/profile');
        if (response.ok) {
            const user = await response.json();
            showMessage('Profile loaded successfully!', 'success');
            showUserSection(user);
        } else {
            const error = await response.json();
            showMessage(`Failed to load profile: ${error.message}`, 'error');
            if (response.status === 401) {
                // Token expired or invalid
                currentToken = null;
                localStorage.removeItem('bearer_token');
                showAuthSection();
            }
        }
    } catch (error) {
        showMessage(`Profile error: ${error.message}`, 'error');
    }
});

// Handle logout button click
document.getElementById('logout-btn').addEventListener('click', logout);

// Handle logout
async function logout() {
    try {
        if (currentToken) {
            await makeAuthenticatedRequest('/auth/logout', { method: 'POST' });
        }

        currentToken = null;
        localStorage.removeItem('bearer_token');
        showMessage('Logged out successfully!', 'success');
        showAuthSection();
    } catch (error) {
        showMessage(`Logout error: ${error.message}`, 'error');
    }
}

// Check if user is already authenticated on page load
async function checkAuthStatus() {
    if (!currentToken) {
        return; // No token, stay on login page
    }

    try {
        const response = await makeAuthenticatedRequest('/auth/profile');
        if (response.ok) {
            const user = await response.json();
            showUserSection(user);
        } else {
            // Token invalid, clear it
            currentToken = null;
            localStorage.removeItem('bearer_token');
        }
    } catch (error) {
        // User not authenticated, stay on login page
        console.log('User not authenticated');
    }
}

// Check auth status when page loads
document.addEventListener('DOMContentLoaded', checkAuthStatus);