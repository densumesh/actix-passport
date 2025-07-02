# Actix Passport

A full-featured, extensible authentication framework for [actix-web](https://actix.rs/) in Rust.

## Features

- 🔐 **Multiple Authentication Methods**
  - Username/password authentication with secure Argon2 hashing
  - OAuth 2.0 support (Google, GitHub, and custom providers)
  - JWT token authentication
  - Session-based authentication

- 🏗️ **Flexible Architecture**
  - Pluggable user and session stores (database-agnostic)
  - Customizable password hashing algorithms
  - Extensible OAuth provider system
  - Builder pattern for easy configuration

- 🚀 **Developer Friendly**
  - Minimal boilerplate with sensible defaults
  - Type-safe extractors for authenticated users
  - Comprehensive documentation and examples
  - Feature flags for optional functionality

- 🛡️ **Security First**
  - CSRF protection for OAuth flows
  - Secure session management
  - Configurable CORS policies
  - Password strength validation

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
actix-passport = "0.1"
actix-web = "4.4"
actix-session = "0.8"
tokio = { version = "1.0", features = ["full"] }
```

### Basic Setup

```rust
use actix_passport::{
    AuthBuilder, AuthenticatedUser, OptionalAuthenticatedUser,
    InMemoryUserStore, InMemorySessionStore
};
use actix_session::{config::PersistentSession, storage::CookieSessionStore, SessionMiddleware};
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};

#[get("/")]
async fn home(user: OptionalAuthenticatedUser) -> impl Responder {
    match user.0 {
        Some(user) => HttpResponse::Ok().json(format!("Welcome, {}!", user.id)),
        None => HttpResponse::Ok().json("Welcome! Please log in."),
    }
}

#[get("/dashboard")]
async fn dashboard(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().json(format!("Dashboard for user: {}", user.0.id))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Set up stores (use database implementations in production)
    let user_store = InMemoryUserStore::new();
    let session_store = InMemorySessionStore::new();
    
    // Configure authentication
    let auth = AuthBuilder::new()
        .user_store(user_store)
        .session_store(session_store)
        .enable_password_auth()
        .with_google_oauth(
            "your_google_client_id".to_string(),
            "your_google_client_secret".to_string(),
        )
        .build();

    HttpServer::new(move || {
        let session_middleware = SessionMiddleware::new(
            CookieSessionStore::default(),
            actix_web::cookie::Key::generate(),
        );

        App::new()
            .wrap(session_middleware)
            .wrap(auth.middleware())
            .service(home)
            .service(dashboard)
            .service(
                web::scope("/auth")
                    .configure(|cfg| auth.configure_routes(cfg))
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

### Available Endpoints

Once configured, your app automatically gets these authentication endpoints:

- `POST /auth/login` - Login with email/password
- `POST /auth/register` - Register new user
- `POST /auth/logout` - Logout current user
- `GET /auth/me` - Get current user info
- `GET /auth/{provider}` - OAuth login (e.g., `/auth/google`)
- `GET /auth/{provider}/callback` - OAuth callback

### Custom User Store

Implement the `UserStore` trait for your database:

```rust
use actix_passport::{UserStore, AuthUser, AuthResult};
use async_trait::async_trait;

pub struct DatabaseUserStore {
    // Your database connection
}

#[async_trait]
impl UserStore for DatabaseUserStore {
    async fn find_by_id(&self, id: &str) -> AuthResult<Option<AuthUser>> {
        // Your database query logic
        todo!()
    }

    async fn find_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>> {
        // Your database query logic
        todo!()
    }

    async fn create_user(&self, user: AuthUser) -> AuthResult<AuthUser> {
        // Your user creation logic
        todo!()
    }

    // ... implement other required methods
}
```

### Custom OAuth Provider

```rust
use actix_passport::{OAuthProvider, OAuthUser, AuthResult};
use async_trait::async_trait;

pub struct CustomOAuthProvider {
    client_id: String,
    client_secret: String,
}

#[async_trait]
impl OAuthProvider for CustomOAuthProvider {
    fn name(&self) -> &str {
        "custom"
    }

    fn authorize_url(&self, state: &str, redirect_uri: &str) -> AuthResult<String> {
        // Generate OAuth authorization URL
        todo!()
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AuthResult<OAuthUser> {
        // Exchange code for user info
        todo!()
    }
}
```

## Examples

See the [`examples/`](examples/) directory for complete working examples:

- [`basic.rs`](examples/basic.rs) - Basic password authentication
- [`oauth.rs`](examples/oauth.rs) - OAuth with Google and GitHub
- [`database.rs`](examples/database.rs) - Using with a real database
- [`jwt.rs`](examples/jwt.rs) - JWT token authentication
- [`custom.rs`](examples/custom.rs) - Custom providers and stores

## Feature Flags

Control which features to include:

```toml
[dependencies]
actix-passport = { version = "0.1", features = ["password", "oauth", "jwt"] }
```

Available features:
- `password` (default) - Username/password authentication
- `oauth` (default) - OAuth 2.0 providers
- `jwt` (default) - JWT token support

## Architecture

### Core Components

- **`UserStore`** - Interface for user persistence (database, file, etc.)
- **`SessionStore`** - Interface for session management (Redis, database, memory)
- **`PasswordHasher`** - Interface for password hashing (Argon2, bcrypt, etc.)
- **`OAuthProvider`** - Interface for OAuth providers (Google, GitHub, custom)

### Middleware

- **`AuthMiddleware`** - Session-based authentication middleware
- **`JwtAuthMiddleware`** - JWT token authentication middleware

### Extractors

- **`AuthenticatedUser`** - Requires authentication, returns user or 401
- **`OptionalAuthenticatedUser`** - Optional authentication, returns `Option<User>`

## Configuration

```rust
use actix_passport::{AuthConfig, RouteConfig};
use chrono::Duration;

let auth_config = AuthConfig {
    session_duration: Duration::days(30),
    jwt_secret: Some("your-secret-key".to_string()),
    allowed_origins: vec!["https://yourapp.com".to_string()],
    require_email_verification: true,
    password_reset_expiry: Duration::hours(1),
};

let route_config = RouteConfig {
    login_success_redirect: Some("/dashboard".to_string()),
    logout_redirect: Some("/".to_string()),
    oauth_callback_base: "https://yourapp.com/auth".to_string(),
};

let auth = AuthBuilder::new()
    .with_config(auth_config)
    .with_route_config(route_config)
    // ... other configuration
    .build();
```

## Testing

Run the test suite:

```bash
cargo test
```

Run the example server:

```bash
cargo run --example basic
# or
cargo run  # runs the main.rs example
```

Then test the endpoints:

```bash
# Register a new user
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "secure_password", "username": "testuser"}'

# Login
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"identifier": "user@example.com", "password": "secure_password"}'

# Access protected endpoint
curl http://localhost:8080/dashboard \
  -H "Cookie: actix-passport-session=your_session_cookie"
```

## Production Considerations

### Security

1. **Use HTTPS in production** - Set `cookie_secure(true)` for session middleware
2. **Use strong JWT secrets** - Generate cryptographically secure random keys
3. **Implement rate limiting** - Protect login endpoints from brute force attacks
4. **Enable CSRF protection** - Validate state parameters in OAuth flows
5. **Use secure session storage** - Redis or database instead of memory stores

### Database Integration

For production use, implement stores with your database of choice:

```rust
// Example with SQLx and PostgreSQL
use sqlx::PgPool;

#[derive(Clone)]
pub struct PostgresUserStore {
    pool: PgPool,
}

#[async_trait]
impl UserStore for PostgresUserStore {
    async fn find_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>> {
        let user = sqlx::query_as!(
            AuthUser,
            "SELECT * FROM users WHERE email = $1",
            email
        )
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(user)
    }
    
    // ... implement other methods
}
```

### Performance

- Use connection pooling for database stores
- Implement session cleanup jobs for expired sessions
- Consider Redis for session storage in multi-instance deployments
- Enable gzip compression for JSON responses

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.