//! OAuth authentication module.
//!
//! This module provides OAuth 2.0 authentication support for various providers
//! like Google, GitHub, etc. It includes provider implementations and
//! utilities for handling OAuth flows.

/// OAuth provider implementations for various services.
pub mod providers;
/// OAuth service for managing multiple providers.
pub mod service;

use crate::types::AuthResult;
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
