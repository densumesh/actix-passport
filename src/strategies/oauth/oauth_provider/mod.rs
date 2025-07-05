//! OAuth authentication module.
//!
//! This module provides OAuth 2.0 authentication support for various providers
//! like Google, GitHub, etc. It includes provider implementations and
//! utilities for handling OAuth flows.

/// OAuth provider implementations for various services.
pub mod providers;

use crate::{types::AuthResult, AuthUser};
use async_trait::async_trait;
use dyn_clone::DynClone;
use serde::{Deserialize, Serialize};

/// OAuth configuration for a provider.
///
/// This struct contains the necessary configuration for setting up
/// OAuth authentication with a specific provider.
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// OAuth client ID
    pub client_id: String,
    /// OAuth client secret
    pub client_secret: String,
    /// Authorization endpoint URL
    pub auth_url: String,
    /// Token exchange endpoint URL
    pub token_url: String,
    /// User info endpoint URL
    pub user_info_url: String,
    /// OAuth scopes to request
    pub scopes: Vec<String>,
}

impl OAuthConfig {
    /// Creates a new builder for `OAuthConfig`.
    #[must_use]
    pub const fn builder(client_id: String, client_secret: String) -> OAuthConfigBuilder {
        OAuthConfigBuilder::new(client_id, client_secret)
    }
}

/// Builder for `OAuthConfig`.
pub struct OAuthConfigBuilder {
    client_id: String,
    client_secret: String,
    auth_url: Option<String>,
    token_url: Option<String>,
    user_info_url: Option<String>,
    scopes: Vec<String>,
}

impl OAuthConfigBuilder {
    /// Creates a new `OAuthConfigBuilder`.
    #[must_use]
    pub const fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
            auth_url: None,
            token_url: None,
            user_info_url: None,
            scopes: Vec::new(),
        }
    }

    /// Sets the authorization URL.
    #[must_use]
    pub fn auth_url(mut self, url: impl Into<String>) -> Self {
        self.auth_url = Some(url.into());
        self
    }

    /// Sets the token URL.
    #[must_use]
    pub fn token_url(mut self, url: impl Into<String>) -> Self {
        self.token_url = Some(url.into());
        self
    }

    /// Sets the user info URL.
    #[must_use]
    pub fn user_info_url(mut self, url: impl Into<String>) -> Self {
        self.user_info_url = Some(url.into());
        self
    }

    /// Adds a scope to the list of requested scopes.
    #[must_use]
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    /// Builds the `OAuthConfig`.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the required URLs are not set.
    pub fn build(self) -> AuthResult<OAuthConfig> {
        Ok(OAuthConfig {
            client_id: self.client_id,
            client_secret: self.client_secret,
            auth_url: self.auth_url.ok_or_else(|| {
                crate::errors::AuthError::ConfigurationError {
                    message: "auth_url is required".to_string(),
                    suggestions: vec!["Call .auth_url() on the builder".to_string()],
                }
            })?,
            token_url: self.token_url.ok_or_else(|| {
                crate::errors::AuthError::ConfigurationError {
                    message: "token_url is required".to_string(),
                    suggestions: vec!["Call .token_url() on the builder".to_string()],
                }
            })?,
            user_info_url: self.user_info_url.ok_or_else(|| {
                crate::errors::AuthError::ConfigurationError {
                    message: "user_info_url is required".to_string(),
                    suggestions: vec!["Call .user_info_url() on the builder".to_string()],
                }
            })?,
            scopes: self.scopes,
        })
    }
}

/// OAuth token response from provider.
///
/// This represents the response received when exchanging an authorization
/// code for an access token.
#[derive(Debug, Serialize, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

/// Represents user information returned from an OAuth provider.
///
/// This struct contains the user information that OAuth providers
/// return after successful authentication.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
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

impl From<OAuthUser> for AuthUser {
    fn from(user: OAuthUser) -> Self {
        Self::new(uuid::Uuid::new_v4().to_string())
            .with_email(user.email.as_deref().unwrap_or_default())
            .with_username(user.username.as_deref().unwrap_or_default())
            .with_display_name(user.display_name.as_deref().unwrap_or_default())
            .with_avatar_url(user.avatar_url.as_deref().unwrap_or_default())
            .with_oauth_provider(user)
    }
}

/// Trait for OAuth provider implementations.
///
/// This trait defines the interface for OAuth providers like Google, GitHub, etc.
/// Each provider implements this trait to handle OAuth flow specifics.
///
/// # Examples
///
/// ```rust
/// use actix_passport::{AuthResult, oauth_provider::{OAuthProvider, OAuthUser}};
/// use async_trait::async_trait;
///
/// #[derive(Clone)]
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
///     fn authorize_url(&self, state: &str, redirect_uri: &str) -> AuthResult<String> {
///         Ok(format!(
///             "https://accounts.google.com/oauth/authorize?client_id={}&redirect_uri={}&state={}",
///             self.client_id, redirect_uri, state
///         ))
///     }
///     
///     async fn exchange_code(&self, _code: &str, _redirect_uri: &str) -> AuthResult<OAuthUser> {
///         // Implementation here
///         Ok(OAuthUser {
///             provider: "google".to_string(),
///             provider_id: "123".to_string(),
///             email: Some("user@gmail.com".to_string()),
///             username: None,
///             display_name: Some("User".to_string()),
///             avatar_url: None,
///             raw_data: serde_json::json!({}),
///         })
///     }
/// }
/// ```
#[async_trait]
pub trait OAuthProvider: Send + Sync + DynClone {
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
    ///
    /// # Errors
    ///
    /// Returns an error if the authorization URL cannot be generated.
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
    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AuthResult<OAuthUser>;
}

dyn_clone::clone_trait_object!(OAuthProvider);
