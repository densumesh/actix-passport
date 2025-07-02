use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::errors::AuthError;

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
    /// Creates a new `AuthUser` with the given ID.
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
    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Sets the username for the user.
    ///
    /// # Arguments
    ///
    /// * `username` - The user's username
    #[must_use]
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Sets the display name for the user.
    ///
    /// # Arguments
    ///
    /// * `display_name` - The user's display name
    #[must_use]
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

/// Type alias for authentication results.
///
/// This is a convenience type that represents a `Result` with `AuthError` as the error type.
pub type AuthResult<T> = Result<T, AuthError>;
