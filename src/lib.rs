//! # Actix Passport
//!
//! A comprehensive, flexible authentication framework for [actix-web](https://actix.rs/) applications in Rust.
//!
//! ## Features
//!
//! - **Multiple Authentication Methods**: Username/password (with Argon2 hashing), OAuth 2.0, and session-based authentication
//! - **Pluggable Architecture**: Database-agnostic user stores, extensible OAuth providers
//! - **Security First**: Built-in CSRF protection, secure session management, configurable CORS policies
//! - **Developer Friendly**: Minimal boilerplate, type-safe extractors, comprehensive documentation
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use actix_passport::prelude::*;
//! use actix_web::{web, App, HttpServer};
//! use actix_session::{SessionMiddleware, storage::CookieSessionStore};
//! use actix_web::cookie::Key;
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     // Configure authentication framework with convenience methods
//!     let auth_framework = ActixPassportBuilder::with_in_memory_store()
//!         .enable_password_auth()  // Easy password authentication setup
//!         .build();
//!
//!     HttpServer::new(move || {
//!         App::new()
//!             // Session middleware is required for authentication
//!             .wrap(SessionMiddleware::builder(
//!                 CookieSessionStore::default(),
//!                 Key::from(&[0; 64])
//!             ).build())
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

pub mod builder;

/// Core Passport types and functions.
pub mod core;
/// Authentication error types.
pub mod errors;
/// Authentication strategy trait and implementations.
pub mod strategies;
/// Type definitions for authentication.
pub mod types;
/// User store trait and implementations.
pub mod user_store;

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

pub use crate::builder::ActixPassportBuilder;
pub use crate::core::*;
pub use crate::errors::AuthError;
pub use crate::strategies::AuthStrategy;
pub use crate::types::*;

#[cfg(feature = "oauth")]
pub use crate::strategies::oauth::oauth_provider;

// Re-export database stores
#[cfg(feature = "postgres")]
pub use crate::user_store::stores::postgres::{PostgresConfig, PostgresUserStore};
pub use crate::user_store::{stores::in_memory::InMemoryUserStore, UserStore};
