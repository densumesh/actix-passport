use crate::{
    errors::AuthError,
    oauth::{OAuthConfig, OAuthProvider, OAuthUser, TokenResponse},
    types::AuthResult,
};
use async_trait::async_trait;
use reqwest::Client;
use std::collections::HashMap;
use url::Url;

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
#[derive(Clone)]
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
            .map_err(|e| AuthError::OAuth(format!("Invalid auth URL: {e}")))?;

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

        token_params.insert("client_id", self.config.client_id.as_str());
        token_params.insert("client_secret", self.config.client_secret.as_str());
        token_params.insert("code", code);
        token_params.insert("redirect_uri", redirect_uri);
        token_params.insert("grant_type", "authorization_code");

        let token_response = self
            .client
            .post(&self.config.token_url)
            .form(&token_params)
            .send()
            .await
            .map_err(|e| AuthError::OAuth(format!("Token request failed: {e}")))?;

        if !token_response.status().is_success() {
            return Err(AuthError::OAuth(format!(
                "Token request failed with status: {}",
                token_response.status()
            )));
        }

        let token_data: TokenResponse = token_response
            .json()
            .await
            .map_err(|e| AuthError::OAuth(format!("Invalid token response: {e}")))?;

        // Get user information using access token
        let user_response = self
            .client
            .get(&self.config.user_info_url)
            .bearer_auth(&token_data.access_token)
            .send()
            .await
            .map_err(|e| AuthError::OAuth(format!("User info request failed: {e}")))?;

        if !user_response.status().is_success() {
            return Err(AuthError::OAuth(format!(
                "User info request failed with status: {}",
                user_response.status()
            )));
        }

        let user_data: serde_json::Value = user_response
            .json()
            .await
            .map_err(|e| AuthError::OAuth(format!("Invalid user info response: {e}")))?;

        // Extract common user fields (this is generic, specific providers should override)
        let oauth_user = OAuthUser {
            provider: self.name.clone(),
            provider_id: user_data["id"]
                .as_str()
                .or_else(|| user_data["sub"].as_str())
                .unwrap_or("unknown")
                .to_string(),
            email: user_data["email"]
                .as_str()
                .map(std::string::ToString::to_string),
            username: user_data["login"]
                .as_str()
                .or_else(|| user_data["username"].as_str())
                .map(std::string::ToString::to_string),
            display_name: user_data["name"]
                .as_str()
                .or_else(|| user_data["display_name"].as_str())
                .map(std::string::ToString::to_string),
            avatar_url: user_data["avatar_url"]
                .as_str()
                .or_else(|| user_data["picture"].as_str())
                .map(std::string::ToString::to_string),
            raw_data: user_data,
        };

        Ok(oauth_user)
    }
}
