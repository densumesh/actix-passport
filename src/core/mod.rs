//! Core authentication types and traits for actix-passport.
//!
//! This module provides the fundamental building blocks for the authentication system,
//! including user representation, session management, and error handling.

use async_trait::async_trait;
use dyn_clone::DynClone;
use uuid::Uuid;

use crate::types::{AuthResult, AuthUser, Session};

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
/// struct MyUserStore;
///
/// #[async_trait]
/// impl UserStore for MyUserStore {
///     async fn find_by_id(&self, id: &str) -> AuthResult<Option<AuthUser>> {
///         // Implementation here
///         Ok(None)
///     }
///     
///     // ... other methods
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

/// Trait for storing and managing user sessions.
///
/// This trait defines the interface for session persistence and management.
/// Implementors can use any storage backend (Redis, database, memory, etc.).
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Creates a new session.
    ///
    /// # Arguments
    ///
    /// * `session` - The session to create
    async fn create_session(&self, session: Session) -> AuthResult<Session>;
    /// Finds a session by its ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The session ID
    async fn find_session(&self, id: Uuid) -> AuthResult<Option<Session>>;
    /// Updates an existing session.
    ///
    /// # Arguments
    ///
    /// * `session` - The session with updated information
    async fn update_session(&self, session: Session) -> AuthResult<Session>;
    /// Deletes a session.
    ///
    /// # Arguments
    ///
    /// * `id` - The session ID to delete
    async fn delete_session(&self, id: Uuid) -> AuthResult<()>;
    /// Deletes all sessions for a specific user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user ID whose sessions to delete
    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()>;
    /// Cleans up expired sessions.
    ///
    /// # Returns
    ///
    /// Returns the number of expired sessions that were cleaned up.
    async fn cleanup_expired_sessions(&self) -> AuthResult<u64>;
}

/// Configuration for the authentication system.
///
/// This struct contains all the configuration options for the authentication system,
/// including session settings, JWT configuration, and security options.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// How long sessions should last before expiring
    pub session_duration: chrono::Duration,
    /// Secret key for JWT token signing (optional)
    pub jwt_secret: Option<String>,
    /// List of allowed origins for CORS
    pub allowed_origins: Vec<String>,
    /// Whether email verification is required for new users
    pub require_email_verification: bool,
    /// How long password reset tokens should be valid
    pub password_reset_expiry: chrono::Duration,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            session_duration: chrono::Duration::days(30),
            jwt_secret: None,
            allowed_origins: vec!["http://localhost:3000".to_string()],
            require_email_verification: false,
            password_reset_expiry: chrono::Duration::hours(1),
        }
    }
}
