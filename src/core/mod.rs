//! Core authentication types and traits for actix-passport.
//!
//! This module provides the fundamental building blocks for the authentication system,
//! including user representation, and error handling.

use async_trait::async_trait;
use dyn_clone::DynClone;

use crate::types::{AuthResult, AuthUser};

/// Trait for storing and retrieving user data.
///
/// This trait defines the interface for user persistence. Implementors
/// can use any storage backend (database, file system, etc.).
///
/// # Examples
///
/// ```rust
/// use actix_passport::{UserStore, AuthUser, AuthResult};
/// use async_trait::async_trait;
///
/// #[derive(Clone)]
/// struct MyUserStore;
///
/// #[async_trait]
/// impl UserStore for MyUserStore {
///     async fn find_by_id(&self, id: &str) -> AuthResult<Option<AuthUser>> {
///         // Implementation here
///         Ok(None)
///     }
///     
///     async fn find_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>> {
///         Ok(None)
///     }
///     
///     async fn find_by_username(&self, username: &str) -> AuthResult<Option<AuthUser>> {
///         Ok(None)
///     }
///     
///     async fn create_user(&self, user: AuthUser) -> AuthResult<AuthUser> {
///         Ok(user)
///     }
///     
///     async fn update_user(&self, user: AuthUser) -> AuthResult<AuthUser> {
///         Ok(user)
///     }
///     
///     async fn delete_user(&self, _id: &str) -> AuthResult<()> {
///         Ok(())
///     }
/// }
/// ```
#[async_trait]
pub trait UserStore: Send + Sync + DynClone {
    /// Finds a user by their unique ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The user's unique identifier
    ///
    /// # Returns
    ///
    /// Returns `Ok(Some(user))` if found, `Ok(None)` if not found, or an error.
    async fn find_by_id(&self, id: &str) -> AuthResult<Option<AuthUser>>;
    /// Finds a user by their email address.
    ///
    /// # Arguments
    ///
    /// * `email` - The user's email address
    async fn find_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>>;
    /// Finds a user by their username.
    ///
    /// # Arguments
    ///
    /// * `username` - The user's username
    async fn find_by_username(&self, username: &str) -> AuthResult<Option<AuthUser>>;
    /// Creates a new user in the store.
    ///
    /// # Arguments
    ///
    /// * `user` - The user to create
    ///
    /// # Returns
    ///
    /// Returns the created user, potentially with updated fields (e.g., generated ID).
    async fn create_user(&self, user: AuthUser) -> AuthResult<AuthUser>;
    /// Updates an existing user in the store.
    ///
    /// # Arguments
    ///
    /// * `user` - The user with updated information
    async fn update_user(&self, user: AuthUser) -> AuthResult<AuthUser>;
    /// Deletes a user from the store.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the user to delete
    async fn delete_user(&self, id: &str) -> AuthResult<()>;
}

dyn_clone::clone_trait_object!(UserStore);

/// Configuration for the authentication system.
///
/// This struct contains all the configuration options for the authentication system,
/// including session settings, JWT configuration, and security options.
#[derive(Debug, Clone, Default)]
pub(crate) struct AuthConfig {
    /// Whether password authentication is enabled
    pub(crate) password_auth: bool,
    /// Whether OAuth authentication is enabled
    pub(crate) oauth_auth: bool,
}
