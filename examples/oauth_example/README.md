# OAuth Example

This example demonstrates how to use **actix-passport** with OAuth providers (Google and GitHub) alongside traditional password authentication.

## Features

- **OAuth 2.0 Authentication**: Google and GitHub OAuth providers
- **Password Authentication**: Traditional username/password login
- **Session Management**: Secure session handling with actix-session
- **Modern Frontend**: Responsive web interface with real-time authentication
- **Multiple Auth Methods**: Users can choose between OAuth and password authentication

## Setup

### 1. OAuth Provider Configuration

To use OAuth authentication, you need to set up applications with the OAuth providers:

#### Google OAuth Setup
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API
4. Create credentials (OAuth 2.0 Client ID)
5. Add `http://127.0.0.1:8080/auth/google/callback` to authorized redirect URIs

#### GitHub OAuth Setup
1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Create a new OAuth App
3. Set Authorization callback URL to `http://127.0.0.1:8080/auth/github/callback`

### 2. Environment Configuration

1. Copy the environment template:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and add your OAuth credentials:
   ```env
   GOOGLE_CLIENT_ID=your_google_client_id_here
   GOOGLE_CLIENT_SECRET=your_google_client_secret_here
   GITHUB_CLIENT_ID=your_github_client_id_here
   GITHUB_CLIENT_SECRET=your_github_client_secret_here
   ```

### 3. Run the Example

From the `examples/oauth_example` directory:

```bash
cargo run
```

The server will start at `http://127.0.0.1:8080`

## Usage

### OAuth Authentication

1. **Google OAuth**: Click "Continue with Google" to authenticate with your Google account
2. **GitHub OAuth**: Click "Continue with GitHub" to authenticate with your GitHub account

### Password Authentication

1. **Register**: Create a new account with username, email, and password
2. **Login**: Sign in with your username and password

### API Endpoints

- `GET /` - Main frontend page
- `GET /auth/google` - Initiate Google OAuth flow
- `GET /auth/github` - Initiate GitHub OAuth flow
- `GET /auth/google/callback` - Google OAuth callback
- `GET /auth/github/callback` - GitHub OAuth callback
- `POST /auth/login` - Password login
- `POST /auth/register` - User registration
- `POST /auth/logout` - Logout
- `GET /api/user` - Get current user info (requires authentication)
- `GET /api/health` - Health check endpoint

## Architecture

### Backend Components

- **ActixPassportBuilder**: Configures the authentication framework
- **OAuth Providers**: Google and GitHub OAuth providers
- **UserStore**: In-memory user storage for demonstration
- **Session Management**: Cookie-based sessions via actix-session
- **Route Configuration**: Automatic OAuth route registration

### Frontend Components

- **OAuth Buttons**: Direct links to OAuth provider endpoints
- **Password Forms**: Login and registration forms
- **User Dashboard**: Shows authenticated user information
- **Session Handling**: Maintains authentication state

### Security Features

- **CSRF Protection**: OAuth state parameter validation
- **Session Security**: Secure cookie-based sessions
- **Input Validation**: Form validation on both client and server
- **Error Handling**: Comprehensive error messages and logging

## Code Structure

```
oauth_example/
├── src/
│   └── main.rs           # Main application with OAuth configuration
├── static/
│   ├── index.html        # Frontend HTML
│   └── app.js           # JavaScript for auth handling
├── .env.example         # Environment template
├── Cargo.toml          # Dependencies
└── README.md           # This file
```

## Customization

### Adding New OAuth Providers

1. Use the `GenericOAuthProvider` for custom OAuth 2.0 providers:
   ```rust
   use actix_passport::oauth::providers::GenericOAuthProvider;
   use actix_passport::oauth::OAuthConfig;
   
   let custom_config = OAuthConfig::builder(client_id, client_secret)
       .auth_url("https://provider.com/oauth/authorize")
       .token_url("https://provider.com/oauth/token")
       .user_info_url("https://provider.com/api/user")
       .scope("read:user")
       .build()?;
   
   let custom_provider = GenericOAuthProvider::new("custom", custom_config);
   ```

2. Add the provider to your framework:
   ```rust
   let auth_framework = ActixPassportBuilder::new()
       .with_user_store(user_store)
       .with_oauth(custom_provider)
       .build()?;
   ```

### Customizing User Storage

Replace the `InMemoryUserStore` with your own implementation:

```rust
use actix_passport::core::UserStore;

#[derive(Clone)]
struct MyUserStore {
    // Your database connection, etc.
}

#[async_trait]
impl UserStore for MyUserStore {
    // Implement required methods
}
```

## Production Considerations

1. **Environment Variables**: Use a secure method to manage secrets
2. **Session Keys**: Use a cryptographically secure session key
3. **HTTPS**: Enable HTTPS in production
4. **Database**: Replace in-memory storage with persistent database
5. **Error Handling**: Implement proper error logging and monitoring
6. **Rate Limiting**: Add rate limiting for authentication endpoints
7. **CSRF Protection**: Ensure CSRF tokens are properly validated

## Troubleshooting

### Common Issues

1. **OAuth Callback Errors**: Ensure redirect URIs match exactly in your OAuth provider settings
2. **Missing Environment Variables**: Check that all required environment variables are set
3. **Session Issues**: Verify that session middleware is properly configured
4. **CORS Issues**: Add CORS middleware if accessing from different origins

### Debug Logging

Enable debug logging by setting the environment variable:
```bash
RUST_LOG=debug cargo run
```

This will show detailed OAuth flow information and help diagnose issues.