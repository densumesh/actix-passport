# Actix Passport

[![Crates.io](https://img.shields.io/crates/v/actix-passport.svg)](https://crates.io/crates/actix-passport)
[![Documentation](https://docs.rs/actix-passport/badge.svg)](https://docs.rs/actix-passport)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

A comprehensive, flexible authentication framework for [actix-web](https://actix.rs/) applications in Rust.

## Features

- **Multiple Authentication Methods**
  - Username/password authentication with secure Argon2 hashing
  - OAuth 2.0 support (Google, GitHub, and custom providers)
  - Session-based authentication

- **Flexible Architecture**
  - Pluggable user stores (database-agnostic)
  - Extensible OAuth provider system
  - Builder pattern for easy configuration
  - Type-safe authentication extractors

- **Developer Friendly**
  - Minimal boilerplate with sensible defaults
  - Comprehensive documentation and examples
  - Feature flags for optional functionality
  - Built-in authentication routes

- **Security First**
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
use actix_passport::prelude::*;
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder, cookie::Key};

#[get("/")]
async fn home(user: OptionalAuthedUser) -> impl Responder {
    match user.0 {
        Some(user) => HttpResponse::Ok().json(format!("Welcome, {}!", user.id)),
        None => HttpResponse::Ok().json("Welcome! Please log in."),
    }
}

#[get("/dashboard")]
async fn dashboard(user: AuthedUser) -> impl Responder {
    HttpResponse::Ok().json(format!("Dashboard for user: {}", user.id))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Simple setup with in-memory store (for development)
    let auth_framework = ActixPassportBuilder::with_in_memory_store()
        .enable_password_auth()
        .build();

    HttpServer::new(move || {
        App::new()
            // Session middleware is required
            .wrap(SessionMiddleware::builder(
                CookieSessionStore::default(),
                Key::generate()
            ).build())
            .service(home)
            .service(dashboard)
            .configure(|cfg| auth_framework.configure_routes(cfg, RouteConfig::default()))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

### Production Setup with PostgreSQL

```rust
use actix_passport::prelude::*;
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::{web, App, HttpServer, cookie::Key};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let auth_framework = ActixPassportBuilder::with_postgres_store(
            "postgres://user:password@localhost/myapp"
        )
        .await
        .unwrap()
        .enable_password_auth()
        .with_google_oauth(
            "your_google_client_id".to_string(),
            "your_google_client_secret".to_string()
        )
        .build();

    HttpServer::new(move || {
        App::new()
            .wrap(SessionMiddleware::builder(
                CookieSessionStore::default(),
                Key::generate()
            ).build())
            .configure(|cfg| auth_framework.configure_routes(cfg, RouteConfig::default()))
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
use actix_passport::{user_store::UserStore, types::{AuthUser, AuthResult}};
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

    async fn find_by_username(&self, username: &str) -> AuthResult<Option<AuthUser>> {
        // Your database query logic
        todo!()
    }

    async fn create_user(&self, user: AuthUser) -> AuthResult<AuthUser> {
        // Your user creation logic
        todo!()
    }

    async fn update_user(&self, user: AuthUser) -> AuthResult<AuthUser> {
        // Your user update logic
        todo!()
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        // Your user deletion logic
        todo!()
    }
}
```

### Custom OAuth Provider

```rust
use actix_passport::{oauth::{OAuthProvider, OAuthUser}, types::AuthResult};
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

- [`basic_example/`](examples/basic_example/) - Basic password authentication
- [`oauth_example/`](examples/oauth_example/) - OAuth with Google and GitHub
- [`postgres_example/`](examples/postgres_example/) - Example with PostgreSQL user store
- [`advanced_example/`](examples/advanced_example/) - Advanced example with SQLite and Bearer token authentication

## Feature Flags

Control which features to include:

```toml
[dependencies]
actix-passport = { version = "0.1", features = ["password", "oauth"] }
```

Available features:
- `password` (default) - Username/password authentication
- `oauth` (default) - OAuth 2.0 providers
- `postgres` - PostgreSQL user store

## Architecture

### Core Components

- **`UserStore`** - Interface for user persistence (database, file, etc.)
- **`ActixPassport`** - Main framework object containing all configured services
- **`AuthStrategy`** - Interface for authentication strategies

### Extractors
- **`AuthedUser`** - Requires authentication, returns user or 401
- **`OptionalAuthedUser`** - Optional authentication, returns `Option<User>`


## Testing

Run the test suite:

```bash
cargo test
```

Run the example servers:

```bash
cd examples/basic_example && cargo run
# or for OAuth example
cd examples/oauth_example && cargo run
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

# Access protected endpoint (session cookie is set automatically after login)
curl http://localhost:8080/dashboard \
  --cookie-jar cookies.txt --cookie cookies.txt
```

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.