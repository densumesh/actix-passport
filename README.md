# Actix Passport

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
use actix_passport::{
    ActixPassportBuilder, AuthedUser, OptionalAuthedUser,
    user_store::UserStore, types::{AuthResult, AuthUser}
};
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use async_trait::async_trait;

// Implement your user store (use a real database in production)
#[derive(Clone)]
struct MyUserStore;

#[async_trait]
impl UserStore for MyUserStore {
    async fn find_by_id(&self, _id: &str) -> AuthResult<Option<AuthUser>> {
        // Your database implementation here
        Ok(None)
    }
    // ... implement other required methods
    async fn find_by_email(&self, _email: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
    async fn find_by_username(&self, _username: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
    async fn create_user(&self, user: AuthUser) -> AuthResult<AuthUser> { Ok(user) }
    async fn update_user(&self, user: AuthUser) -> AuthResult<AuthUser> { Ok(user) }
    async fn delete_user(&self, _id: &str) -> AuthResult<()> { Ok(()) }
}

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
    // Configure authentication framework
    let auth_framework = ActixPassportBuilder::new(MyUserStore)
        .enable_password_auth()
        .build();

    HttpServer::new(move || {
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                actix_web::cookie::Key::generate(),
            ))
            .app_data(web::Data::new(auth_framework.clone()))
            .service(home)
            .service(dashboard)
            .configure(|cfg| auth_framework.configure_routes(cfg))
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

## Feature Flags

Control which features to include:

```toml
[dependencies]
actix-passport = { version = "0.1", features = ["password", "oauth"] }
```

Available features:
- `password` (default) - Username/password authentication
- `oauth` (default) - OAuth 2.0 providers

## Architecture

### Core Components

- **`UserStore`** - Interface for user persistence (database, file, etc.)
- **`PasswordAuthService`** - Service for password authentication using Argon2 hashing
- **`OAuthProvider`** - Interface for OAuth providers (Google, GitHub, custom)
- **`ActixPassport`** - Main framework object containing all configured services

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


## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.