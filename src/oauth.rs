//! OAuth authentication module.
//!
//! This module provides OAuth 2.0 authentication support for various providers
//! like Google, GitHub, etc. It includes provider implementations and
//! utilities for handling OAuth flows.

use crate::core::{AuthError, AuthResult, OAuthProvider, OAuthUser};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

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

/// Generic OAuth provider implementation.
///
/// This is a generic OAuth provider that can work with any OAuth 2.0
/// compliant service. For specific providers like Google or GitHub,
/// you can use the specialized implementations or create your own.
///
/// # Examples
///
/// ```rust
/// use actix_passport::{GenericOAuthProvider, OAuthConfig};
///
/// let config = OAuthConfig {
///     client_id: "your_client_id".to_string(),
///     client_secret: "your_client_secret".to_string(),
///     auth_url: "https://provider.com/oauth/authorize".to_string(),
///     token_url: "https://provider.com/oauth/token".to_string(),
///     user_info_url: "https://provider.com/api/user".to_string(),
///     scopes: vec!["read:user".to_string(), "user:email".to_string()],
/// };
///
/// let provider = GenericOAuthProvider::new("custom", config);
/// ```
pub struct GenericOAuthProvider {
    name: String,
    config: OAuthConfig,
    client: Client,
}

impl GenericOAuthProvider {
    /// Creates a new generic OAuth provider.
    ///
    /// # Arguments
    ///
    /// * `name` - A unique name for this provider (e.g., "google", "github")
    /// * `config` - OAuth configuration for this provider
    pub fn new(name: impl Into<String>, config: OAuthConfig) -> Self {
        Self {
            name: name.into(),
            config,
            client: Client::new(),
        }
    }
}

#[async_trait]
impl OAuthProvider for GenericOAuthProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn authorize_url(&self, state: &str, redirect_uri: &str) -> AuthResult<String> {
        let mut url = Url::parse(&self.config.auth_url)
            .map_err(|e| AuthError::OAuth(format!("Invalid auth URL: {}", e)))?;

        url.query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("state", state)
            .append_pair("scope", &self.config.scopes.join(" "));

        Ok(url.to_string())
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AuthResult<OAuthUser> {
        // Exchange authorization code for access token
        let mut token_params = HashMap::new();
        token_params.insert("client_id", &self.config.client_id);
        token_params.insert("client_secret", &self.config.client_secret);
        token_params.insert("code", code);
        token_params.insert("redirect_uri", redirect_uri);
        token_params.insert("grant_type", &"authorization_code".to_string());

        let token_response = self
            .client
            .post(&self.config.token_url)
            .form(&token_params)
            .send()
            .await
            .map_err(|e| AuthError::OAuth(format!("Token request failed: {}", e)))?;

        if !token_response.status().is_success() {
            return Err(AuthError::OAuth(format!(
                "Token request failed with status: {}",
                token_response.status()
            )));
        }

        let token_data: TokenResponse = token_response
            .json()
            .await
            .map_err(|e| AuthError::OAuth(format!("Invalid token response: {}", e)))?;

        // Get user information using access token
        let user_response = self
            .client
            .get(&self.config.user_info_url)
            .bearer_auth(&token_data.access_token)
            .send()
            .await
            .map_err(|e| AuthError::OAuth(format!("User info request failed: {}", e)))?;

        if !user_response.status().is_success() {
            return Err(AuthError::OAuth(format!(
                "User info request failed with status: {}",
                user_response.status()
            )));
        }

        let user_data: serde_json::Value = user_response
            .json()
            .await
            .map_err(|e| AuthError::OAuth(format!("Invalid user info response: {}", e)))?;

        // Extract common user fields (this is generic, specific providers should override)
        let oauth_user = OAuthUser {
            provider: self.name.clone(),
            provider_id: user_data["id"]
                .as_str()
                .or_else(|| user_data["sub"].as_str())
                .unwrap_or("unknown")
                .to_string(),
            email: user_data["email"].as_str().map(|s| s.to_string()),
            username: user_data["login"]
                .as_str()
                .or_else(|| user_data["username"].as_str())
                .map(|s| s.to_string()),
            display_name: user_data["name"]
                .as_str()
                .or_else(|| user_data["display_name"].as_str())
                .map(|s| s.to_string()),
            avatar_url: user_data["avatar_url"]
                .as_str()
                .or_else(|| user_data["picture"].as_str())
                .map(|s| s.to_string()),
            raw_data: user_data,
        };

        Ok(oauth_user)
    }
}

/// Google OAuth provider implementation.
///
/// This is a specialized OAuth provider for Google authentication.
/// It handles Google-specific OAuth flow and user data extraction.
///
/// # Examples
///
/// ```rust
/// use actix_passport::GoogleOAuthProvider;
///
/// let provider = GoogleOAuthProvider::new(
///     "your_google_client_id".to_string(),
///     "your_google_client_secret".to_string(),
/// );
/// ```
pub struct GoogleOAuthProvider {
    inner: GenericOAuthProvider,
}

impl GoogleOAuthProvider {
    /// Creates a new Google OAuth provider.
    ///
    /// # Arguments
    ///
    /// * `client_id` - Google OAuth client ID
    /// * `client_secret` - Google OAuth client secret
    pub fn new(client_id: String, client_secret: String) -> Self {
        let config = OAuthConfig {
            client_id,
            client_secret,
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            user_info_url: "https://www.googleapis.com/oauth2/v2/userinfo".to_string(),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
        };

        Self {
            inner: GenericOAuthProvider::new("google", config),
        }
    }
}

#[async_trait]
impl OAuthProvider for GoogleOAuthProvider {
    fn name(&self) -> &str {
        "google"
    }

    fn authorize_url(&self, state: &str, redirect_uri: &str) -> AuthResult<String> {
        self.inner.authorize_url(state, redirect_uri)
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AuthResult<OAuthUser> {
        self.inner.exchange_code(code, redirect_uri).await
    }
}

/// GitHub OAuth provider implementation.
///
/// This is a specialized OAuth provider for GitHub authentication.
/// It handles GitHub-specific OAuth flow and user data extraction.
///
/// # Examples
///
/// ```rust
/// use actix_passport::GitHubOAuthProvider;
///
/// let provider = GitHubOAuthProvider::new(
///     "your_github_client_id".to_string(),
///     "your_github_client_secret".to_string(),
/// );
/// ```
pub struct GitHubOAuthProvider {
    inner: GenericOAuthProvider,
}

impl GitHubOAuthProvider {
    /// Creates a new GitHub OAuth provider.
    ///
    /// # Arguments
    ///
    /// * `client_id` - GitHub OAuth client ID
    /// * `client_secret` - GitHub OAuth client secret
    pub fn new(client_id: String, client_secret: String) -> Self {
        let config = OAuthConfig {
            client_id,
            client_secret,
            auth_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            user_info_url: "https://api.github.com/user".to_string(),
            scopes: vec!["user:email".to_string()],
        };

        Self {
            inner: GenericOAuthProvider::new("github", config),
        }
    }
}

#[async_trait]
impl OAuthProvider for GitHubOAuthProvider {
    fn name(&self) -> &str {
        "github"
    }

    fn authorize_url(&self, state: &str, redirect_uri: &str) -> AuthResult<String> {
        self.inner.authorize_url(state, redirect_uri)
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AuthResult<OAuthUser> {
        let mut oauth_user = self.inner.exchange_code(code, redirect_uri).await?;

        // GitHub doesn't always include email in the user info response
        // We need to make a separate request to get the user's email
        if oauth_user.email.is_none() {
            if let Ok(email) = self.fetch_github_email(&oauth_user.raw_data).await {
                oauth_user.email = Some(email);
            }
        }

        Ok(oauth_user)
    }
}

impl GitHubOAuthProvider {
    /// Fetches the user's primary email from GitHub API.
    ///
    /// GitHub sometimes doesn't include the email in the user info response,
    /// so we need to make a separate API call to get it.
    async fn fetch_github_email(&self, _user_data: &serde_json::Value) -> AuthResult<String> {
        // This would require the access token from the previous request
        // For now, we'll just return an error
        Err(AuthError::OAuth(
            "Email fetching not implemented yet".to_string(),
        ))
    }
}

/// OAuth service for managing multiple OAuth providers.
///
/// This service manages multiple OAuth providers and provides a unified
/// interface for OAuth operations across different providers.
///
/// # Examples
///
/// ```rust
/// use actix_passport::{OAuthService, GoogleOAuthProvider, GitHubOAuthProvider};
/// use std::sync::Arc;
///
/// let mut oauth_service = OAuthService::new();
/// oauth_service.add_provider(Arc::new(GoogleOAuthProvider::new(
///     "google_client_id".to_string(),
///     "google_client_secret".to_string(),
/// )));
/// oauth_service.add_provider(Arc::new(GitHubOAuthProvider::new(
///     "github_client_id".to_string(),
///     "github_client_secret".to_string(),
/// )));
/// ```
pub struct OAuthService {
    providers: HashMap<String, Box<dyn OAuthProvider>>,
}

impl OAuthService {
    /// Creates a new OAuth service.
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }

    /// Adds an OAuth provider to the service.
    ///
    /// # Arguments
    ///
    /// * `provider` - The OAuth provider to add
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::{OAuthService, GoogleOAuthProvider};
    ///
    /// let mut service = OAuthService::new();
    /// service.add_provider(Box::new(GoogleOAuthProvider::new(
    ///     "client_id".to_string(),
    ///     "client_secret".to_string(),
    /// )));
    /// ```
    pub fn add_provider(&mut self, provider: Box<dyn OAuthProvider>) {
        let name = provider.name().to_string();
        self.providers.insert(name, provider);
    }

    /// Gets an OAuth provider by name.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the provider
    ///
    /// # Returns
    ///
    /// Returns a reference to the provider if found.
    pub fn get_provider(&self, name: &str) -> Option<&dyn OAuthProvider> {
        self.providers.get(name).map(|p| p.as_ref())
    }

    /// Lists all available provider names.
    ///
    /// # Returns
    ///
    /// Returns a vector of provider names.
    pub fn list_providers(&self) -> Vec<&str> {
        self.providers.keys().map(|s| s.as_str()).collect()
    }

    /// Generates an authorization URL for a specific provider.
    ///
    /// # Arguments
    ///
    /// * `provider_name` - The name of the OAuth provider
    /// * `state` - CSRF protection state parameter
    /// * `redirect_uri` - URI to redirect to after authorization
    ///
    /// # Returns
    ///
    /// Returns the authorization URL for the specified provider.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider is not found.
    pub fn authorize_url(
        &self,
        provider_name: &str,
        state: &str,
        redirect_uri: &str,
    ) -> AuthResult<String> {
        let provider = self
            .get_provider(provider_name)
            .ok_or_else(|| AuthError::OAuth(format!("Provider '{}' not found", provider_name)))?;

        provider.authorize_url(state, redirect_uri)
    }

    /// Exchanges an authorization code for user information.
    ///
    /// # Arguments
    ///
    /// * `provider_name` - The name of the OAuth provider
    /// * `code` - The authorization code from the provider
    /// * `redirect_uri` - The redirect URI used in the authorization request
    ///
    /// # Returns
    ///
    /// Returns the user information from the OAuth provider.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider is not found or the code exchange fails.
    pub async fn exchange_code(
        &self,
        provider_name: &str,
        code: &str,
        redirect_uri: &str,
    ) -> AuthResult<OAuthUser> {
        let provider = self
            .get_provider(provider_name)
            .ok_or_else(|| AuthError::OAuth(format!("Provider '{}' not found", provider_name)))?;

        provider.exchange_code(code, redirect_uri).await
    }
}

impl Default for OAuthService {
    fn default() -> Self {
        Self::new()
    }
}