use crate::{
    strategies::oauth::oauth_provider::providers::generic_provider::GenericOAuthProvider,
    strategies::oauth::oauth_provider::{OAuthConfig, OAuthProvider, OAuthUser},
    types::AuthResult,
};
use async_trait::async_trait;
use std::env;

/// GitHub OAuth provider implementation.
///
/// This is a specialized OAuth provider for GitHub authentication.
/// It handles GitHub-specific OAuth flow and user data extraction.
///
/// Ensure that you have allowed `<domain>/auth/github/callback` as an authorized redirect URI
///
/// # Examples
///
/// ```rust
/// use actix_passport::oauth_provider::providers::GitHubOAuthProvider;
///
/// let provider = GitHubOAuthProvider::new(
///     "your_github_client_id".to_string(),
///     "your_github_client_secret".to_string(),
/// );
/// ```
#[derive(Clone)]
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
    #[must_use]
    pub fn new(client_id: String, client_secret: String) -> Self {
        let config = OAuthConfig {
            client_id,
            client_secret,
            auth_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            user_info_url: "https://api.github.com/user".to_string(),
            scopes: vec!["user".to_string()],
        };

        Self {
            inner: GenericOAuthProvider::new("github", config),
        }
    }

    /// Creates a new GitHub OAuth provider from environment variables.
    /// Expects `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` to be set.
    #[must_use]
    pub fn from_env() -> Self {
        let client_id = env::var("GITHUB_CLIENT_ID").unwrap_or_default();
        let client_secret = env::var("GITHUB_CLIENT_SECRET").unwrap_or_default();
        Self::new(client_id, client_secret)
    }
}

#[async_trait]
impl OAuthProvider for GitHubOAuthProvider {
    fn name(&self) -> &'static str {
        "github"
    }

    fn authorize_url(&self, state: &str, redirect_uri: &str) -> AuthResult<String> {
        self.inner.authorize_url(state, redirect_uri)
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AuthResult<OAuthUser> {
        let user = self.inner.exchange_code(code, redirect_uri).await?;
        let github_user = OAuthUser {
            username: user.raw_data["login"].as_str().map(ToString::to_string),
            display_name: user.raw_data["name"].as_str().map(ToString::to_string),
            ..user
        };

        Ok(github_user)
    }
}
