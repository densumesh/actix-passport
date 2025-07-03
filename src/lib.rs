//! # Actix Passport
//!
//! A comprehensive, flexible authentication framework for [actix-web](https://actix.rs/) applications in Rust.
//!
//! ## Features
//!
//! - **Multiple Authentication Methods**: Username/password (with Argon2 hashing), OAuth 2.0, JWT tokens, and session-based authentication
//! - **Pluggable Architecture**: Database-agnostic user stores, extensible OAuth providers
//! - **Security First**: Built-in CSRF protection, secure session management, configurable CORS policies
//! - **Developer Friendly**: Minimal boilerplate, type-safe extractors, comprehensive documentation
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use actix_passport::{ActixPassportBuilder, user_store::UserStore, types::{AuthResult, AuthUser}};
//! use actix_web::{web, App, HttpServer};
//! use actix_session::SessionMiddleware;
//! use async_trait::async_trait;
//!
//! // Implement your user store
//! #[derive(Clone)]
//! struct MyUserStore;
//!
//! #[async_trait]
//! impl UserStore for MyUserStore {
//!     async fn find_by_id(&self, id: &str) -> AuthResult<Option<AuthUser>> {
//!         // Your implementation
//!         Ok(None)
//!     }
//!     // ... implement other required methods
//! #   async fn find_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
//! #   async fn find_by_username(&self, username: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
//! #   async fn create_user(&self, user: AuthUser) -> AuthResult<AuthUser> { Ok(user) }
//! #   async fn update_user(&self, user: AuthUser) -> AuthResult<AuthUser> { Ok(user) }
//! #   async fn delete_user(&self, id: &str) -> AuthResult<()> { Ok(()) }
//! }
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     // Configure authentication framework
//!     let auth_framework = ActixPassportBuilder::new(MyUserStore)
//!         .enable_password_auth()  // Uses Argon2 hashing internally
//!         .build();
//!
//!     HttpServer::new(move || {
//!         App::new()
//!             .configure(|cfg| auth_framework.configure_routes(cfg))
//!     })
//!     .bind("127.0.0.1:8080")?
//!     .run()
//!     .await
//! }
//! ```
//!
//! ## Available Routes
//!
//! Once configured, your app automatically gets these authentication endpoints:
//!
//! - `POST /auth/register` - Register new user with email/password
//! - `POST /auth/login` - Login with email/username and password
//! - `POST /auth/logout` - Logout current user
//! - `GET /auth/me` - Get current user profile
//! - `GET /auth/{provider}` - Initiate OAuth login
//! - `GET /auth/{provider}/callback` - Handle OAuth callback
//!
//! ## Architecture
//!
//! The framework is built around these core components:
//!
//! - [`ActixPassport`] - Main framework object containing all services
//! - [`user_store::UserStore`] - Trait for user persistence (implement for your database)
//! - [`password::service::PasswordAuthService`] - Service for password-based authentication using Argon2
//! - [`oauth::OAuthProvider`] - Trait for OAuth 2.0 providers
//! - Authentication middleware for session and JWT-based auth

pub mod builder;

/// Authentication error types.
pub mod errors;
pub mod middleware;
pub mod routes;
/// Core type definitions for authentication.
pub mod types;
/// User store trait and implementations.
pub mod user_store;

#[cfg(feature = "password")]
pub mod password;

#[cfg(feature = "oauth")]
pub mod oauth;

/// Convenient re-exports of commonly used types.
///
/// This module provides a simple way to import all the types you'll commonly
/// need when working with actix-passport.
///
/// # Examples
///
/// ```rust,no_run
/// use actix_passport::prelude::*;
///
/// // All commonly used types are now available
/// ```
pub mod prelude;

pub use crate::builder::{ActixPassport, ActixPassportBuilder};
pub use crate::middleware::*;
pub use crate::types::*;

#[cfg(feature = "password")]
pub use crate::password::{service::PasswordAuthService, LoginCredentials, RegisterCredentials};

#[cfg(feature = "oauth")]
pub use crate::oauth::{
    providers::{
        generic_provider::GenericOAuthProvider, github_provider::GitHubOAuthProvider,
        google_provider::GoogleOAuthProvider,
    },
    service::OAuthService,
    OAuthConfig, OAuthProvider, OAuthUser,
};
