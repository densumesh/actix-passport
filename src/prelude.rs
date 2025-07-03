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
//! };
//! ```
//!
//! You can now use:
//!
//! ```rust,no_run
//! use actix_passport::prelude::*;
//! ```

// Core framework types
pub use crate::{ActixPassport, ActixPassportBuilder, AuthedUser, OptionalAuthedUser};

// Core types and traits
pub use crate::types::{AuthResult, AuthUser};
pub use crate::user_store::{stores::in_memory::InMemoryUserStore, UserStore};

// Error types
pub use crate::errors::AuthError;

// Password authentication types (feature-gated)
#[cfg(feature = "password")]
pub use crate::password::{LoginCredentials, RegisterCredentials};

// OAuth types and providers (feature-gated)
#[cfg(feature = "oauth")]
pub use crate::oauth::{OAuthConfig, OAuthProvider, OAuthUser};

#[cfg(feature = "oauth")]
pub use crate::{GenericOAuthProvider, GitHubOAuthProvider, GoogleOAuthProvider, OAuthService};

// Re-export commonly used external types
pub use actix_web::{HttpRequest, HttpResponse};
pub use async_trait::async_trait;
pub use serde_json::json;
