//! Prelude module for convenient imports.
//!
//! This module re-exports the most commonly used types and traits from the
//! actix-passport crate, allowing for a single import instead of multiple imports.
//!
//! # Examples
//!
//! Instead of importing from multiple modules:
//!
//! ```rust,no_run
//! use actix_passport::{
//!     user_store::UserStore,
//!     types::{AuthResult, AuthUser},
//!     ActixPassportBuilder, AuthedUser,
//!     strategies::password::PasswordStrategy,
//! };
//! ```
//!
//! You can now use:
//!
//! ```rust,no_run
//! use actix_passport::prelude::*;
//! ```

// Core framework types
pub use crate::{ActixPassport, ActixPassportBuilder, AuthedUser, OptionalAuthedUser, RouteConfig};

// Core types and traits
pub use crate::types::{AuthResult, AuthUser};
pub use crate::{AuthStrategy, UserStore};

// User store implementations
pub use crate::user_store::stores::in_memory::InMemoryUserStore;

// Error types
pub use crate::errors::AuthError;

// Strategy implementations
#[cfg(feature = "password")]
pub use crate::strategies::password::PasswordStrategy;

#[cfg(feature = "oauth")]
pub use crate::strategies::oauth::OAuthStrategy;

// OAuth providers (feature-gated)
#[cfg(feature = "oauth")]
pub use crate::oauth_provider::{OAuthConfig, OAuthProvider, OAuthUser};

#[cfg(feature = "oauth")]
pub use crate::oauth_provider::providers::{
    GenericOAuthProvider, GitHubOAuthProvider, GoogleOAuthProvider,
};

// Database stores
#[cfg(feature = "postgres")]
pub use crate::{PostgresConfig, PostgresUserStore};

// Re-export commonly used external types
pub use actix_web::{HttpRequest, HttpResponse};
pub use async_trait::async_trait;
pub use serde_json::json;
