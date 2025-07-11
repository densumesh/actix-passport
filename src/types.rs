use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{errors::AuthError, oauth_provider::OAuthUser};

pub(crate) const USER_ID_KEY: &str = "actix_passport_user_id";

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
    /// Timestamp when the email was verified (optional)
    #[cfg(feature = "email")]
    pub email_verified_at: Option<DateTime<Utc>>,
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

            #[cfg(feature = "email")]
            email_verified_at: None,
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
    /// use actix_passport::{AuthUser, oauth_provider::OAuthUser};
    /// use serde_json::json;
    ///
    /// let user = AuthUser::new("user123")
    ///     .with_oauth_provider(OAuthUser {
    ///         provider: "github".to_string(),
    ///         provider_id: "github_user_123".to_string(),
    ///         raw_data: json!({
    ///             "username": "johndoe",
    ///             "avatar_url": "https://github.com/johndoe.png"
    ///         }),
    ///         ..Default::default()
    ///     });
    /// ```
    #[must_use]
    pub fn with_oauth_provider(mut self, provider_data: OAuthUser) -> Self {
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
            provider_data.provider.clone(),
            serde_json::to_value(provider_data).unwrap_or_default(),
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
    /// use actix_passport::{AuthUser, oauth_provider::OAuthUser};
    /// use serde_json::json;
    ///
    /// let user = AuthUser::new("user123")
    ///     .with_oauth_provider(OAuthUser {
    ///         provider: "github".to_string(),
    ///         provider_id: "github_123".to_string(),
    ///         ..Default::default()
    ///     })
    ///     .with_oauth_provider(OAuthUser {
    ///         provider: "google".to_string(),
    ///         provider_id: "google_456".to_string(),
    ///         ..Default::default()
    ///     });
    ///
    /// let providers = user.get_oauth_providers();
    /// assert!(providers.iter().any(|p| p.provider == "github"));
    /// assert!(providers.iter().any(|p| p.provider == "google"));
    /// ```
    #[must_use]
    pub fn get_oauth_providers(&self) -> Vec<OAuthUser> {
        self.metadata
            .get("oauth_providers")
            .and_then(|providers| providers.as_object())
            .map(|obj| {
                obj.iter()
                    .map(|(_, value)| serde_json::from_value(value.clone()).unwrap_or_default())
                    .collect()
            })
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
    /// use actix_passport::{AuthUser, oauth_provider::OAuthUser};
    /// use serde_json::json;
    ///
    /// let user = AuthUser::new("user123")
    ///     .with_oauth_provider(OAuthUser {
    ///         provider: "github".to_string(),
    ///         provider_id: "github_123".to_string(),
    ///         ..Default::default()
    ///     });
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

    /// Sets the email verification status.
    ///
    /// # Arguments
    ///
    /// * `verified` - Whether the email is verified
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::AuthUser;
    ///
    /// let user = AuthUser::new("user123")
    ///     .with_email("user@example.com")
    ///     .with_email_verified(true);
    ///
    /// # #[cfg(feature = "email")]
    /// assert!(user.is_email_verified());
    /// ```
    #[cfg(feature = "email")]
    #[must_use]
    pub fn with_email_verified(mut self, verified: bool) -> Self {
        if verified && self.email_verified_at.is_none() {
            self.email_verified_at = Some(Utc::now());
        } else if !verified {
            self.email_verified_at = None;
        }
        self
    }

    /// Checks if the user's email is verified.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::AuthUser;
    ///
    /// let user = AuthUser::new("user123")
    ///     .with_email("user@example.com");
    ///
    /// # #[cfg(feature = "email")]
    /// assert!(!user.is_email_verified());
    /// ```
    #[cfg(feature = "email")]
    #[must_use]
    pub const fn is_email_verified(&self) -> bool {
        self.email_verified_at.is_some()
    }
}

/// Type alias for authentication results.
///
/// This is a convenience type that represents a `Result` with `AuthError` as the error type.
pub type AuthResult<T> = Result<T, AuthError>;
