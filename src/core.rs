//! Core authentication types and traits for actix-passport.
//!
//! This module provides the fundamental building blocks for the authentication system,
//! including user representation, session management, and error handling.

use actix_web::{Error as ActixError, HttpRequest, HttpResponse};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Represents an authenticated user in the system.
///
/// This is the core user type that gets injected into request handlers
/// via the authentication middleware. It contains essential user information
/// and can be extended with custom metadata.
///
/// # Examples
///
/// ```rust
/// use actix_passport::AuthUser;
/// use std::collections::HashMap;
///
/// let user = AuthUser::new("user123")
///     .with_email("user@example.com")
///     .with_username("john_doe")
///     .with_display_name("John Doe");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    /// Unique identifier for the user
    pub id: String,
    /// User's email address (optional)
    pub email: Option<String>,
    /// User's username (optional)
    pub username: Option<String>,
    /// User's display name (optional)
    pub display_name: Option<String>,
    /// URL to user's avatar image (optional)
    pub avatar_url: Option<String>,
    /// Timestamp when the user was created
    pub created_at: DateTime<Utc>,
    /// Timestamp of the user's last login (optional)
    pub last_login: Option<DateTime<Utc>>,
    /// Additional custom metadata for the user
    pub metadata: HashMap<String, serde_json::Value>,
}

impl AuthUser {
    /// Creates a new AuthUser with the given ID.
    ///
    /// # Arguments
    ///
    /// * `id` - A unique identifier for the user
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::AuthUser;
    ///
    /// let user = AuthUser::new("user123");
    /// assert_eq!(user.id, "user123");
    /// ```
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            email: None,
            username: None,
            display_name: None,
            avatar_url: None,
            created_at: Utc::now(),
            last_login: None,
            metadata: HashMap::new(),
        }
    }

    /// Sets the email address for the user.
    ///
    /// # Arguments
    ///
    /// * `email` - The user's email address
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::AuthUser;
    ///
    /// let user = AuthUser::new("user123").with_email("user@example.com");
    /// assert_eq!(user.email, Some("user@example.com".to_string()));
    /// ```
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Sets the username for the user.
    ///
    /// # Arguments
    ///
    /// * `username` - The user's username
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Sets the display name for the user.
    ///
    /// # Arguments
    ///
    /// * `display_name` - The user's display name
    pub fn with_display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }
}

/// Represents a user session.
///
/// Sessions are used to maintain user authentication state across requests.
/// Each session has a unique ID, is associated with a user, and contains
/// expiration information and custom data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier
    pub id: Uuid,
    /// ID of the user this session belongs to
    pub user_id: String,
    /// Timestamp when the session was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the session expires
    pub expires_at: DateTime<Utc>,
    /// Additional session data
    pub data: HashMap<String, serde_json::Value>,
}

/// Authentication-related errors.
///
/// This enum represents all possible errors that can occur during
/// authentication operations.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Session expired")]
    SessionExpired,
    #[error("Unauthorized")]
    Unauthorized,
    #[error("OAuth error: {0}")]
    OAuth(String),
    #[error("Database error: {0}")]
    Database(#[from] anyhow::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<AuthError> for ActixError {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::UserNotFound => ActixError::from(actix_web::error::ErrorNotFound(err)),
            AuthError::InvalidCredentials | AuthError::Unauthorized => {
                ActixError::from(actix_web::error::ErrorUnauthorized(err))
            }
            AuthError::SessionExpired => {
                ActixError::from(actix_web::error::ErrorUnauthorized(err))
            }
            _ => ActixError::from(actix_web::error::ErrorInternalServerError(err)),
        }
    }
}

/// Type alias for authentication results.
///
/// This is a convenience type that represents a `Result` with `AuthError` as the error type.
pub type AuthResult<T> = Result<T, AuthError>;

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
pub trait UserStore: Send + Sync {
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

/// Represents user information returned from an OAuth provider.
///
/// This struct contains the user information that OAuth providers
/// return after successful authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthUser {
    /// Name of the OAuth provider (e.g., "google", "github")
    pub provider: String,
    /// User's ID from the OAuth provider
    pub provider_id: String,
    /// User's email address from the provider
    pub email: Option<String>,
    /// User's username from the provider
    pub username: Option<String>,
    /// User's display name from the provider
    pub display_name: Option<String>,
    /// URL to user's avatar image from the provider
    pub avatar_url: Option<String>,
    /// Raw user data returned by the provider
    pub raw_data: serde_json::Value,
}

/// Trait for OAuth provider implementations.
///
/// This trait defines the interface for OAuth providers like Google, GitHub, etc.
/// Each provider implements this trait to handle OAuth flow specifics.
///
/// # Examples
///
/// ```rust
/// use actix_passport::{OAuthProvider, OAuthUser, AuthResult};
/// use async_trait::async_trait;
///
/// struct GoogleProvider {
///     client_id: String,
///     client_secret: String,
/// }
///
/// #[async_trait]
/// impl OAuthProvider for GoogleProvider {
///     fn name(&self) -> &str {
///         "google"
///     }
///     
///     // ... other methods
/// }
/// ```
#[async_trait]
pub trait OAuthProvider: Send + Sync {
    /// Returns the name of this OAuth provider.
    ///
    /// This should be a lowercase string like "google", "github", etc.
    fn name(&self) -> &str;
    /// Generates the authorization URL for the OAuth flow.
    ///
    /// # Arguments
    ///
    /// * `state` - CSRF protection state parameter
    /// * `redirect_uri` - URI to redirect to after authorization
    ///
    /// # Returns
    ///
    /// Returns the URL the user should be redirected to for authorization.
    fn authorize_url(&self, state: &str, redirect_uri: &str) -> AuthResult<String>;
    /// Exchanges an authorization code for user information.
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code received from the provider
    /// * `redirect_uri` - The redirect URI used in the authorization request
    ///
    /// # Returns
    ///
    /// Returns the user information from the OAuth provider.
    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> AuthResult<OAuthUser>;
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