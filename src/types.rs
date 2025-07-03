use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    #[serde(skip_serializing)]
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

    /// Sets the avatar URL for the user.
    ///
    /// # Arguments
    ///
    /// * `avatar_url` - The user's avatar image URL
    #[must_use]
    pub fn with_avatar_url(mut self, avatar_url: impl Into<String>) -> Self {
        self.avatar_url = Some(avatar_url.into());
        self
    }

    /// Sets the created at timestamp for the user.
    ///
    /// # Arguments
    ///
    /// * `created_at` - The timestamp when the user was created
    #[must_use]
    pub const fn with_created_at(mut self, created_at: DateTime<Utc>) -> Self {
        self.created_at = created_at;
        self
    }

    /// Adds an OAuth provider to the user's metadata.
    ///
    /// This stores information about which OAuth providers the user has connected,
    /// along with provider-specific data like provider user ID.
    ///
    /// # Arguments
    ///
    /// * `provider` - The name of the OAuth provider (e.g., "google", "github")
    /// * `provider_user_id` - The user's ID from the OAuth provider
    /// * `provider_data` - Additional provider-specific data
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::AuthUser;
    /// use serde_json::json;
    ///
    /// let user = AuthUser::new("user123")
    ///     .with_oauth_provider("github", "github_user_123", &json!({
    ///         "username": "johndoe",
    ///         "avatar_url": "https://github.com/johndoe.png"
    ///     }));
    /// ```
    #[must_use]
    pub fn with_oauth_provider(
        mut self,
        provider: impl Into<String>,
        provider_user_id: impl Into<String>,
        provider_data: &serde_json::Value,
    ) -> Self {
        // Get or create the oauth_providers object in metadata
        let mut default_oauth_providers = serde_json::Map::new();
        let oauth_providers = self
            .metadata
            .entry("oauth_providers".to_string())
            .or_insert_with(|| serde_json::json!({}))
            .as_object_mut()
            .unwrap_or(&mut default_oauth_providers);

        // Store provider information
        oauth_providers.insert(
            provider.into(),
            serde_json::json!({
                "provider_user_id": provider_user_id.into(),
                "connected_at": Utc::now(),
                "data": provider_data
            }),
        );

        self
    }

    /// Gets the list of OAuth providers connected to this user.
    ///
    /// Returns a vector of provider names that the user has connected.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::AuthUser;
    /// use serde_json::json;
    ///
    /// let user = AuthUser::new("user123")
    ///     .with_oauth_provider("github", "github_123", &json!({}))
    ///     .with_oauth_provider("google", "google_456", &json!({}));
    ///
    /// let providers = user.get_oauth_providers();
    /// assert!(providers.contains(&"github".to_string()));
    /// assert!(providers.contains(&"google".to_string()));
    /// ```
    #[must_use]
    pub fn get_oauth_providers(&self) -> Vec<String> {
        self.metadata
            .get("oauth_providers")
            .and_then(|providers| providers.as_object())
            .map(|obj| obj.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Checks if the user has connected a specific OAuth provider.
    ///
    /// # Arguments
    ///
    /// * `provider` - The name of the OAuth provider to check
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::AuthUser;
    /// use serde_json::json;
    ///
    /// let user = AuthUser::new("user123")
    ///     .with_oauth_provider("github", "github_123", &json!({}));
    ///
    /// assert!(user.has_oauth_provider("github"));
    /// assert!(!user.has_oauth_provider("google"));
    /// ```
    #[must_use]
    pub fn has_oauth_provider(&self, provider: &str) -> bool {
        self.metadata
            .get("oauth_providers")
            .and_then(|providers| providers.as_object())
            .is_some_and(|obj| obj.contains_key(provider))
    }

    /// Gets OAuth provider data for a specific provider.
    ///
    /// Returns the stored data for the specified OAuth provider, if connected.
    ///
    /// # Arguments
    ///
    /// * `provider` - The name of the OAuth provider
    #[must_use]
    pub fn get_oauth_provider_data(&self, provider: &str) -> Option<&serde_json::Value> {
        self.metadata
            .get("oauth_providers")
            .and_then(|providers| providers.as_object())
            .and_then(|obj| obj.get(provider))
    }
}

/// Type alias for authentication results.
///
/// This is a convenience type that represents a `Result` with `AuthError` as the error type.
pub type AuthResult<T> = Result<T, AuthError>;

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
